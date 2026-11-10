use super::*;

fn t(n:u32)->TermId{TermId::new(n)}
fn reason(atom:u32)->ReasonId{ReasonId::new(2*u64::from(atom)+2)}
fn configured(explicit:bool)->Partition{
    let mut p=Partition::new(8).unwrap();
    assert!(p.register_group_rows_with_representation(&[t(0),t(1),t(2),t(3)],&[40,64,80],explicit));
    p
}
fn same(c:&Partition,e:&Partition){
    let a=c.group_rows_stats();let b=e.group_rows_stats();
    assert!(!a.representation_explicit && b.representation_explicit);
    assert_eq!((a.tracked_live,a.tracked_peak,a.tracked_inserts),(b.tracked_live,b.tracked_peak,b.tracked_inserts));
    assert_eq!((a.tracked_live,a.tracked_peak,a.tracked_inserts),(a.compressed_live,a.compressed_peak,a.compressed_inserts));
    assert_eq!((b.tracked_live,b.tracked_peak,b.tracked_inserts),(b.shadow_live,b.shadow_peak,b.shadow_inserts));
    assert_eq!((a.shadow_live,a.shadow_peak,a.shadow_inserts,b.compressed_live,b.compressed_peak,b.compressed_inserts),(0,0,0,0,0,0));
    assert_eq!((a.fallback_inserts,a.fallback_identity,a.fallback_sequence,a.fallback_unregistered),
               (b.fallback_inserts,b.fallback_identity,b.fallback_sequence,b.fallback_unregistered));
    assert_eq!((a.active_runs,a.codec_heap_bytes),(b.active_runs,b.codec_heap_bytes));
    assert_eq!(c.group_rows_group_stats(),e.group_rows_group_tracked_stats());
    assert_eq!(e.group_rows_group_stats(),vec![(4,0)]);
    assert_eq!(b.explicit_len,a.explicit_len+a.compressed_live);
    assert_eq!(b.explicit_len,e.separation_records.len());assert_eq!(b.explicit_len,e.separation_count());
    assert_eq!(e.separation_count(),c.separation_count());assert_eq!(c.next_state_id,e.next_state_id);
    assert_eq!(c.separation_records(),e.separation_records());
    assert_eq!(c.canonical_disequalities(),e.canonical_disequalities());
    assert_eq!(c.merge_records(),e.merge_records());
    c.validate().unwrap();e.validate().unwrap();
    for i in 0..8 {for j in 0..8 {
        assert_eq!(c.minimum_separation_witness(t(i),t(j)),e.minimum_separation_witness(t(i),t(j)));
        assert_eq!(c.separation_witnesses(t(i),t(j)),e.separation_witnesses(t(i),t(j)));
    }}
}
fn sep(c:&mut Partition,e:&mut Partition,cb:&mut CheckedSeparationBatch,eb:&mut CheckedSeparationBatch,
       a:u32,b:u32,atom:u32,global:bool,expected_eligible:bool){
    let (l,r,id)=(t(a),t(b),reason(atom));
    let can=|p:&Partition|p.group_rows_has_atom(atom) && p.relation(l,r)==Ok(Relation::Unknown)
        && p.group_rows_accepts(l,r,id);
    assert_eq!((can(c),can(e)),(expected_eligible,expected_eligible));
    let apply=|p:&mut Partition,batch:&mut CheckedSeparationBatch|{
        if global || can(p) {p.separate_in_checked_batch(l,r,id,batch)} else {p.separate(l,r,id)}
    };
    assert_eq!(apply(c,cb),apply(e,eb));
    same(c,e);
}

#[test]
fn ablation_representation_differential_both_batch_policies(){
    for global in [false,true] {
        let (mut c,mut e)=(configured(false),configured(true));
        let (mut cb,mut eb)=(c.checked_separation_batch().unwrap(),e.checked_separation_batch().unwrap());
        let (empty_c,empty_e)=(c.snapshot(),e.snapshot());
        macro_rules! insert {($l:expr,$r:expr,$atom:expr,$expected:expr)=>{
            sep(&mut c,&mut e,&mut cb,&mut eb,$l,$r,$atom,global,$expected)
        }}
        insert!(0,1,40,true);
        let (first_c,first_e)=(c.snapshot(),e.snapshot());
        insert!(0,2,41,true);insert!(0,3,42,true);
        let (old_c,old_e)=(c.snapshot(),e.snapshot());
        assert_eq!(c.rollback(first_c),e.rollback(first_e));same(&c,&e);
        insert!(0,1,40,false); // Duplicate: no new edge or tracker advance.
        insert!(0,2,41,false); // Logical position restored; old state ID was not.
        insert!(0,3,42,false);insert!(0,1,10,false);
        let expected=vec![SeparationRecord{left:t(0),right:t(1),reason:reason(40)},
                          SeparationRecord{left:t(0),right:t(1),reason:reason(10)}];
        assert_eq!(e.separation_witnesses(t(1),t(0)).unwrap().unwrap(),expected);
        let ec=e.merge(t(1),t(0),ReasonId::new(11));
        assert_eq!(c.merge(t(1),t(0),ReasonId::new(11)),ec);
        assert!(matches!(ec,Err(PartitionError::Conflict(Conflict::EqualityAgainstDisequality{separations,..})) if separations==expected));
        let (before_c,before_e)=(c.snapshot(),e.snapshot());
        assert_eq!(c.merge(t(2),t(5),ReasonId::new(7)),e.merge(t(2),t(5),ReasonId::new(7)));
        same(&c,&e);insert!(1,2,64,false); // No singleton after the merge.
        assert_eq!(c.rollback(before_c),e.rollback(before_e));same(&c,&e);
        insert!(1,2,64,true);insert!(6,7,19,false);insert!(1,3,65,false);insert!(2,3,80,true);
        assert!(c.rollback(old_c).is_err());assert!(e.rollback(old_e).is_err());same(&c,&e);
        assert_eq!(c.rollback(empty_c),e.rollback(empty_e));same(&c,&e);
        insert!(0,1,40,true);insert!(0,2,41,true); // A fully popped interval opens at a fresh state ID.
        c.finish_group_rows();e.finish_group_rows();insert!(0,3,42,false);
        assert_eq!(c.rollback(empty_c),e.rollback(empty_e));same(&c,&e);
    }
}

#[test]
fn ablation_representation_shadow_never_supplies_a_record_or_hides_corruption(){
    let mut e=configured(true);let before=e.snapshot();
    e.separate(t(0),t(1),reason(40)).unwrap();
    let id=e.trail.last().unwrap().state_id;
    let orig=e.separation_records.remove(&id).unwrap();
    assert!(e.group_rows.get().unwrap().contains(id)); // A live policy shadow still exists.
    assert_eq!(e.row_record(&id),None);assert!(!e.row_exists(id));
    assert_eq!(e.separation_count(),0);assert!(e.separation_records().is_empty());
    assert!(e.separation_witnesses(t(0),t(1)).is_err());assert!(e.minimum_separation_witness(t(1),t(0)).is_err());
    assert!(e.canonical_disequalities().is_err());assert!(e.check_root_adjacency(0).is_err());
    assert!(e.validate().is_err());assert!(e.rollback(before).is_err());assert_eq!(e.group_rows_stats().shadow_live,1);
    let changed=SeparationRecord{left:t(1),right:t(0),reason:reason(7)};
    e.separation_records.insert(id,changed);
    assert_eq!(e.row_record(&id),Some(changed));assert!(e.row_exists(id));
    assert_eq!(e.separation_records(),vec![changed]);
    assert_eq!(e.minimum_separation_witness(t(0),t(1)).unwrap(),Some((changed,false)));
    assert!(e.validate().is_err());assert!(e.rollback(before).is_err()); // Original undo payload disagrees.
    e.separation_records.insert(id,orig);e.validate().unwrap();e.rollback(before).unwrap();
    assert_eq!(e.group_rows_stats().shadow_live,0);assert_eq!(e.separation_count(),0);
}

#[test]
fn ablation_representation_latched_across_registration_rejection_and_seal(){
    for explicit in [false,true] {
        let mut p=configured(explicit);
        assert!(!p.register_group_rows_with_representation(&[t(6),t(7)],&[10],!explicit));
        // Caller supplies no representation on subsequent registrations: keep the original one.
        assert!(p.register_group_rows(&[t(6),t(7)],&[10]));
        assert_eq!(p.group_rows_candidate_arity(40),Some(4));assert_eq!(p.group_rows_candidate_arity(10),Some(2));
        assert_eq!(p.group_rows_candidate_arity(17),None);
        p.separate(t(6),t(7),reason(10)).unwrap();
        let s=p.group_rows_stats();assert_eq!(s.representation_explicit,explicit);
        assert_eq!((s.tracked_live,s.shadow_live,s.explicit_len),(1,usize::from(explicit),usize::from(explicit)));
        assert_eq!(p.group_rows_group_tracked_stats(),vec![(4,0),(2,1)]);
        p.finish_group_rows();assert!(p.group_rows_candidate_arity(10).is_none());
        assert_eq!(p.group_rows_stats().representation_explicit,explicit);
        assert_eq!(p.separation_witnesses(t(7),t(6)).unwrap().unwrap()[0].reason,reason(10));
    }
}

#[test]
fn ablation_representation_normal_registration_uses_requested_implementation(){
    let requested=std::env::var_os("VPR_ROW_REPRESENTATION").is_some_and(|v|v=="explicit");
    let mut p=Partition::new(3).unwrap();
    assert!(p.register_group_rows(&[t(2),t(0),t(1)],&[7,13]));
    p.separate(t(0),t(2),reason(7)).unwrap();
    let s=p.group_rows_stats();
    assert_eq!(s.representation_explicit,requested);assert_eq!(s.tracked_live,1);
    assert_eq!((s.compressed_live,s.explicit_len),(usize::from(!requested),usize::from(requested)));
}
