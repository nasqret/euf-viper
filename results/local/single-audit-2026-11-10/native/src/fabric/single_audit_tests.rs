use super::*;
use crate::fabric::impact::{affected_terms_with_member_index,ImpactCaps,ImpactOutcome};

fn t(v:u32)->TermId{TermId::new(v)}
fn negative(v:u32)->ReasonId{ReasonId::new(2*u64::from(v)+2)}
struct Tmp(PathBuf);
impl Drop for Tmp{fn drop(&mut self){let _=std::fs::remove_file(&self.0);}}
fn setup(triangle:bool)->(Partition,Tmp){
    let mut p=Partition::new(8).unwrap();
    let terms=[t(0),t(1),t(2)];let bases=[10,15];
    assert!(p.register_group_rows_for_virtual_test(&terms,&bases,false,true));
    p.separate(t(0),t(1),negative(10)).unwrap();
    if triangle{
        p.separate(t(0),t(2),negative(11)).unwrap();p.separate(t(1),t(2),negative(15)).unwrap();
    }else{
        p.separate(t(0),t(1),ReasonId::new(5)).unwrap(); // second reason, ordinary
        p.separate(t(0),t(4),ReasonId::new(7)).unwrap(); // purely ordinary neighbor
    }
    let path=std::env::temp_dir().join(format!("vpr-single-audit-{}-{}",std::process::id(),p.partition_id));
    let f=OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
    p.single_audit.set(Box::new(Observer::new(&p,&terms,&bases,f))).unwrap();
    (p,Tmp(path))
}
fn phase(p:&Partition,post:bool)->Phase{p.single_audit.get().unwrap().state.lock().unwrap().p[usize::from(post)]}

#[test]
fn single_audit_completed_ordered_ids_only_and_scope_exclusions(){
    let (p,_tmp)=setup(false);
    p.checked_root_degree(0).unwrap();p.audit_logical_root::<true>(0).unwrap();
    p.audit_logical_root::<false>(0).unwrap();p.separation_witnesses(t(0),t(1)).unwrap();
    assert_eq!(phase(&p,false).0,[0;25]);
    p.check_root_adjacency(0).unwrap();p.check_root_adjacency(7).unwrap();
    let a=phase(&p,false);
    assert_eq!(&a.0[..11],&[2,2,0,1,1,2,2,2,1,2,0]);assert!(a.consistent());
    p.single_fixed();p.check_root_adjacency(1).unwrap();
    let b=phase(&p,true);assert_eq!(&b.0[..11],&[1,1,0,0,1,1,1,1,1,1,0]);
    #[cfg(feature="fabric")]
    {
        p.single_terminal("sat");
        let j:serde_json::Value=serde_json::from_slice(&std::fs::read(&_tmp.0).unwrap()).unwrap();
        assert_eq!(j["complete"],true);assert_eq!(j["fixed"]["duplicated_physical"],2);
        assert_eq!(j["post"]["second_virtual"],1);assert_eq!(j["member_terms"],serde_json::json!([0,1,2]));
    }
}

#[test]
fn single_audit_partial_first_pass_cannot_be_promoted_to_duplicate(){
    let (mut p,_tmp)=setup(false);
    // ID 3 exists, but on 0/4. Both directions of 0/1 bear the same
    // invalid ID after its legitimate physical secondary witness (ID 2).
    for (a,b) in [(0,1),(1,0)]{p.disequalities[a].get_mut(&b).unwrap().insert(3);}
    assert!(p.check_root_adjacency(0).is_err());
    let a=phase(&p,false);
    assert_eq!(&a.0[..11],&[1,0,1,0,0,0,1,0,0,0,0]);assert!(!a.consistent());
    let mut w=Walk::default();let observed=BTreeSet::from([12u64,17]);
    let mut cursor=Some(observed.iter());
    w.second(13,None,&mut cursor);w.end_pair(cursor);
    assert_eq!((w.second,w.duplicate,w.join_errors),(1,0,2));
}

#[test]
fn single_audit_impact_deduplicates_across_roles_not_across_calls(){
    let (mut p,_tmp)=setup(true);p.single_fixed();
    for round in 1..=2 {
        let result=affected_terms_with_member_index(&p,&[(t(0),t(1))],ImpactCaps::unlimited(),true).unwrap();
        assert!(matches!(result,ImpactOutcome::Complete{..}));
        let a=phase(&p,true);
        for base in [11,16]{assert_eq!(&a.0[base..base+5],&[round,2*round,4*round,round,2*round])}
        assert_eq!(a.0[0],4*round);assert!(a.consistent());
    }
    p.disequal_class_representatives(t(0)).unwrap();assert_eq!(phase(&p,true).0[13],8);
    p.merge(t(0),t(5),ReasonId::new(77)).unwrap();assert!(!p.has_virtual_adjacency());
    let before=phase(&p,true);
    affected_terms_with_member_index(&p,&[(t(5),t(1))],ImpactCaps::unlimited(),true).unwrap();
    let a=phase(&p,true);
    assert_eq!(&a.0[16..21],&before.0[16..21]);assert_eq!(a.0[11],3);
    assert_eq!(a.0[14],3);assert_eq!(a.0[15],6);assert!(a.consistent());
}

#[test]
fn single_audit_checked_batch_hits_are_not_root_traversals(){
    let (p,_tmp)=setup(true);let mut batch=p.checked_separation_batch().unwrap();
    batch.check_root(&p,1).unwrap();batch.check_root(&p,1).unwrap();
    let mut independent=p.checked_separation_batch().unwrap();independent.check_root(&p,1).unwrap();
    let a=phase(&p,false);
    assert_eq!(&a.0[21..],&[1,2,1,2]);assert_eq!(a.0[0],2);assert_eq!(a.0[6],0);
    assert_eq!(a.0[8],4);assert!(a.consistent());
}
