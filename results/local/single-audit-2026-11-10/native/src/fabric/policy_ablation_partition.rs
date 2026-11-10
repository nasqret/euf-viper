use super::*;

fn t(i:u32)->TermId {TermId::new(i)}
fn r(i:u64)->ReasonId {ReasonId::new(i)}

#[test]
fn policy_ablation_review_ambient() {
    // No TLS override in this test. Check the actual process-selected store, not its name.
    let mut p=Partition::new(3).unwrap();
    assert!(p.register_group_rows(&[t(1),t(0),t(2)],&[4,9]));
    p.separate(t(0),t(1),r(10)).unwrap();
    let explicit=match std::env::var("VPR_ROW_REPRESENTATION").as_deref() {
        Err(std::env::VarError::NotPresent)|Ok("compact")=>false, Ok("explicit")=>true,
        _=>panic!("invalid review selector"),
    };
    let s=p.group_rows_stats();
    assert_eq!(s.representation_explicit,explicit);
    assert_eq!((s.tracked_live,s.compressed_live,s.shadow_live,p.separation_records.len()),
               (1,usize::from(!explicit),usize::from(explicit),usize::from(explicit)));
    println!("POLICY_ABLATION_REVIEW_AMBIENT {}",if explicit {"explicit"}else{"compact"});
}

#[test]
fn policy_ablation_review_rollback() {
    for explicit in [false,true] {
        let mut p=Partition::new(6).unwrap();let mut ordinary=Partition::new(6).unwrap();
        assert!(p.register_group_rows_with_representation(&[t(3),t(0),t(2)],&[10,0],explicit));
        let (zero,old_zero)=(p.snapshot(),ordinary.snapshot());
        macro_rules! same { ($call:ident($($a:expr),*)) => {
            assert_eq!(p.$call($($a),*),ordinary.$call($($a),*))
        } }
        same!(separate(t(0),t(3),r(22)));same!(separate(t(2),t(3),r(24)));
        let (prefix,old_prefix)=(p.snapshot(),ordinary.snapshot());
        same!(separate(t(0),t(2),r(2)));
        let (lost,old_lost)=(p.snapshot(),ordinary.snapshot());
        same!(separate(t(3),t(0),r(22))); // reversed duplicate has no undo entry
        same!(separate(t(3),t(0),r(55))); // same pair, fallback second reason
        same!(merge(t(4),t(3),r(101))); same!(merge(t(5),t(0),r(103)));
        same!(separation_witnesses(t(4),t(5)));same!(minimum_separation_witness(t(5),t(4)));
        same!(merge(t(5),t(4),r(105)));
        assert_eq!(p.rollback(prefix),ordinary.rollback(old_prefix));
        same!(separate(t(0),t(2),r(2)));
        assert!(p.rollback(lost).is_err() && ordinary.rollback(old_lost).is_err());
        same!(separation_records());same!(canonical_disequalities());
        assert_eq!(p.group_rows_stats().tracked_live,3);
        assert_eq!(p.separation_records.len(),if explicit {3}else{0});
        p.finish_group_rows();
        assert_eq!(p.rollback(zero),ordinary.rollback(old_zero));
        assert_eq!((p.group_rows_stats().tracked_live,p.separation_count()),(0,0));
        same!(separate(t(0),t(3),r(22)));
        assert_eq!(p.separation_records.len(),1); // sealed reassertion is never promoted
        same!(separation_records());p.validate().unwrap();ordinary.validate().unwrap();
    }
}

#[test]
fn policy_ablation_review_table_authority() {
    let mut p=Partition::new(5).unwrap();
    assert!(p.register_group_rows_with_representation(&[t(0),t(1),t(2)],&[9,1],true));
    let empty=p.snapshot();
    p.separate(t(0),t(1),r(20)).unwrap(); let direct=p.snapshot();
    let (&id,&original)=p.separation_records.iter().next().unwrap();
    p.merge(t(3),t(0),r(9)).unwrap(); p.merge(t(4),t(1),r(11)).unwrap();
    assert_eq!(p.separation_witnesses(t(4),t(3)).unwrap(),Some(vec![original]));
    p.separation_records.remove(&id);
    assert_eq!(p.group_rows_stats().shadow_live,1);
    assert!(p.row_record(&id).is_none() && !p.row_exists(id));
    assert_eq!(p.separation_count(),0);assert!(p.separation_records().is_empty());
    assert!(p.separation_witnesses(t(4),t(3)).is_err());
    assert!(p.minimum_separation_witness(t(3),t(4)).is_err());
    assert!(p.canonical_disequalities().is_err() && p.validate().is_err());
    let other=SeparationRecord{left:t(1),right:t(0),reason:r(201)};
    p.separation_records.insert(id,other);
    assert_eq!(p.separation_witnesses(t(3),t(4)).unwrap(),Some(vec![other]));
    assert_eq!(p.minimum_separation_witness(t(3),t(4)).unwrap(),Some((other,false)));
    assert_eq!(p.separation_records(),vec![other]);
    p.separation_records.insert(id,original);p.rollback(direct).unwrap();
    p.separation_records.insert(id,other);
    assert!(p.preflight_undo(&p.trail.last().unwrap().undo).is_err());
    p.separation_records.insert(id,original);p.rollback(empty).unwrap();
    assert_eq!((p.group_rows_stats().shadow_live,p.separation_count()),(0,0));
    p.validate().unwrap();
}
