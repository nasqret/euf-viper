//! Finite differential checks of the partition, including the physical backing, not a solver benchmark.
use super::*;

fn t(x: u32) -> TermId { TermId::new(x) }
fn r(x: u64) -> ReasonId { ReasonId::new(x) }
fn negative(atom: u32) -> ReasonId { r(2 * u64::from(atom) + 2) }

impl Partition {
    // Bypass all logical/virtual accessors so the original-source proof can distinguish ownership.
    pub(crate) fn proof_test_physical_ids_between(&self, x: TermId, y: TermId) -> usize {
        let a = self.root_of_term(x).unwrap();
        let b = self.root_of_term(y).unwrap();
        let fwd = self.disequalities[a].get(&b);
        assert_eq!(fwd, self.disequalities[b].get(&a));
        fwd.map_or(0, |s| s.len())
    }
}

fn pair(p: &mut Partition, q: &mut Partition, a: u32, b: u32, why: ReasonId) -> SeparationOutcome {
    let want = q.separate(t(a), t(b), why).unwrap();
    assert_eq!(p.separate(t(a), t(b), why), Ok(want));
    want
}

fn check(p: &Partition, q: &Partition) {
    p.validate().unwrap();
    q.validate().unwrap();
    assert_eq!(p.snapshot().depth(), q.snapshot().depth());
    assert_eq!(p.snapshot().state_id, q.snapshot().state_id);
    assert_eq!(p.next_state_id, q.next_state_id);
    assert_eq!(p.classes(), q.classes());
    assert_eq!(p.merge_records(), q.merge_records());
    assert_eq!(p.update_endpoints_since(0), q.update_endpoints_since(0));
    assert_eq!(p.separation_count(), q.separation_count());
    assert_eq!(p.separation_records(), q.separation_records());
    assert_eq!(p.disequality_edge_count(), q.disequality_edge_count());
    assert_eq!(p.canonical_disequalities(), q.canonical_disequalities());
}

fn check_small(p: &Partition, q: &Partition) {
    check(p,q);
    for a in 0..p.term_count() as u32 {
        assert_eq!(p.disequal_class_representatives(t(a)), q.disequal_class_representatives(t(a)));
        for b in 0..p.term_count() as u32 {
            assert_eq!(p.relation(t(a),t(b)), q.relation(t(a),t(b)));
            assert_eq!(p.equality_truth(t(a),t(b)), q.equality_truth(t(a),t(b)));
            assert_eq!(p.disequality_truth(t(a),t(b)), q.disequality_truth(t(a),t(b)));
            assert_eq!(p.separation_witnesses(t(a),t(b)), q.separation_witnesses(t(a),t(b)));
            assert_eq!(p.minimum_separation_witness(t(a),t(b)), q.minimum_separation_witness(t(a),t(b)));
            assert_eq!(p.disequality_reasons(t(a),t(b)), q.disequality_reasons(t(a),t(b)));
            for (nc,nt) in [(0,20),(1,2),(4,0),(2,3),(20,20)] {
                assert_eq!(p.prospective_merge_incidence_terms(t(a),t(b),nc,nt),
                           q.prospective_merge_incidence_terms(t(a),t(b),nc,nt));
            }
        }
    }
}

fn setup(n: usize, terms: &[u32], bases: &[u32], explicit: bool, on: bool) -> (Partition,Partition) {
    let mut p=Partition::new(n).unwrap();
    assert!(p.register_group_rows_for_virtual_test(&terms.iter().copied().map(t).collect::<Vec<_>>(),
                                                 bases,explicit,on));
    (p,Partition::new(n).unwrap())
}

#[test]
fn virtual_adjacency_prefix_order_duplicate_mixed_and_admission() {
    // Source order is deliberately not physical-root or atom-number order.
    let members=[4,1,5,0,3];
    let bases=[90,23,70,38];
    for (explicit,on) in [(false,true),(false,false),(true,true)] {
        let (mut p,mut q)=setup(9,&members,&bases,explicit,on);
        pair(&mut p,&mut q,6,8,r(3));
        let virtual_ok=on && !explicit;
        let mut count=0;
        for i in 0..members.len()-1 {
            for j in i+1..members.len() {
                let (a,b)=(members[i].min(members[j]),members[i].max(members[j]));
                let why=negative(bases[i]+(j-i-1) as u32);
                assert!(pair(&mut p,&mut q,a,b,why).changed());
                count+=1;
                assert_eq!(p.virtual_adjacency_stats().live_pairs,if virtual_ok{count}else{0});
                let snap=p.snapshot();
                assert_eq!(pair(&mut p,&mut q,b,a,why),SeparationOutcome::AlreadyPresent);
                assert_eq!(p.snapshot(),snap);
                check_small(&p,&q);
            }
        }
        // Ordinary lower signed reason on the same already virtual pair; no new neighbor.
        assert_eq!(pair(&mut p,&mut q,4,1,r(9)),SeparationOutcome::Added{relation_was_known:true});
        pair(&mut p,&mut q,1,7,r(77));
        check_small(&p,&q);
        let witnesses=p.separation_witnesses(t(1),t(4)).unwrap().unwrap();
        assert_eq!(witnesses,vec![
            SeparationRecord{left:t(1),right:t(4),reason:negative(90)},
            SeparationRecord{left:t(4),right:t(1),reason:r(9)},
        ]);
        assert_eq!(p.minimum_separation_witness(t(1),t(4)).unwrap().unwrap(),(witnesses[1],false));
        assert_eq!(p.proof_test_physical_ids_between(t(1),t(4)),if virtual_ok{1}else{2});
        assert_eq!(p.physical_adjacency_incidences(),2*(q.separation_count()-if virtual_ok{count}else{0}));
        let before=p.snapshot();
        let rejected=p.merge(t(4),t(1),r(377));
        assert_eq!(rejected,q.merge(t(4),t(1),r(377)));
        assert!(matches!(rejected,Err(PartitionError::Conflict(Conflict::EqualityAgainstDisequality{separations,..}))
                         if separations==witnesses));
        assert_eq!(p.snapshot(),before);
        assert_eq!(p.virtual_adjacency_stats().live_pairs,if virtual_ok{count}else{0});
    }
}

#[test]
fn virtual_adjacency_rollback_before_merge_two_tokens_and_stale_branch() {
    let (mut p,mut q)=setup(7,&[0,1,2,3],&[7,20,31],false,true);
    let start=(p.snapshot(),q.snapshot());
    let mut u=p.checked_separation_batch().unwrap();
    let mut v=p.checked_separation_batch().unwrap();
    let mut x=q.checked_separation_batch().unwrap();
    let mut y=q.checked_separation_batch().unwrap();
    macro_rules! sep {
        ($a:expr,$b:expr,$w:expr,$pt:expr,$qt:expr) => {{
            let got=p.separate_in_checked_batch(t($a),t($b),$w,$pt);
            assert_eq!(got,q.separate_in_checked_batch(t($a),t($b),$w,$qt));
            assert!(got.unwrap().changed());
        }}
    }
    sep!(0,1,negative(7),&mut u,&mut x);
    let prefix=(p.snapshot(),q.snapshot());
    sep!(0,2,negative(8),&mut v,&mut y);
    sep!(0,3,negative(9),&mut u,&mut x);
    let old=(p.snapshot(),q.snapshot());
    assert_eq!(p.rollback(p.snapshot()),Ok(0));
    assert_eq!(p.virtual_adjacency_stats().live_pairs,3);
    assert_eq!(p.rollback(prefix.0),q.rollback(prefix.1));
    let s=p.virtual_adjacency_stats();
    assert_eq!((s.live_pairs,s.materialized_pairs,s.rollback_flushes),(0,3,1));
    assert_eq!(p.physical_adjacency_incidences(),2);
    check_small(&p,&q);
    assert_eq!(p.rollback(old.0),Err(PartitionError::InvalidSnapshot(SnapshotError::FutureState)));
    sep!(0,2,negative(8),&mut v,&mut y);
    sep!(0,3,negative(9),&mut u,&mut x);
    assert_eq!(p.rollback(old.0),q.rollback(old.1));
    assert_eq!(p.rollback(old.0),Err(PartitionError::InvalidSnapshot(SnapshotError::DiscardedBranch)));
    assert_eq!(p.virtual_adjacency_stats().live_pairs,0);
    assert!(p.next_state_id>old.0.state_id);
    assert_eq!(p.merge(t(3),t(6),r(301)),q.merge(t(3),t(6),r(301)));
    check_small(&p,&q);
    assert_eq!(p.rollback(start.0),q.rollback(start.1));
    assert_eq!(p.virtual_adjacency_stats().materializations,1);
    check_small(&p,&q);
}

#[test]
fn virtual_adjacency_exhaustion_conflict_invalid_and_foreign_do_not_flush() {
    let (mut p,mut q)=setup(7,&[0,1,2,3],&[7,20,31],false,true);
    pair(&mut p,&mut q,0,1,negative(7));
    let snap=p.snapshot();
    let mut token=q.checked_separation_batch().unwrap();
    assert!(matches!(p.separate_in_checked_batch(t(0),t(4),r(25),&mut token),Err(PartitionError::InvariantViolation(_))));
    assert_eq!(p.rollback(q.snapshot()),Err(PartitionError::InvalidSnapshot(SnapshotError::ForeignPartition)));
    p.next_state_id=u64::MAX;q.next_state_id=u64::MAX;
    assert_eq!(p.merge(t(0),t(99),r(81)),q.merge(t(0),t(99),r(81)));
    assert_eq!(p.merge(t(0),t(1),r(81)),q.merge(t(0),t(1),r(81)));
    assert_eq!(p.merge(t(4),t(4),r(81)),q.merge(t(4),t(4),r(81)));
    assert_eq!(p.separate(t(1),t(0),negative(7)),Ok(SeparationOutcome::AlreadyPresent));
    assert_eq!(p.merge(t(0),t(4),r(81)),Err(PartitionError::StateIdExhausted));
    assert_eq!(p.separate(t(1),t(4),r(51)),Err(PartitionError::StateIdExhausted));
    let s=p.virtual_adjacency_stats();
    assert_eq!((s.live_pairs,s.materializations,p.physical_adjacency_incidences()),(1,0,0));
    assert_eq!(p.snapshot(),snap);
    check_small(&p,&q);
}

#[test]
fn virtual_adjacency_capacity_barrier_and_physical_corruption() {
    let (mut p,mut q)=setup(7,&[0,1,2,3],&[7,20,31],false,true);
    pair(&mut p,&mut q,0,1,negative(7));
    assert!(p.set_virtual_plain_limit_for_test(0));
    pair(&mut p,&mut q,0,6,r(91));
    let s=p.virtual_adjacency_stats();
    assert_eq!((s.live_pairs,s.capacity_flushes,s.materialized_pairs),(0,1,1));
    check_small(&p,&q);
    let (mut p,mut q)=setup(7,&[0,1,2,3],&[7,20,31],false,true);
    pair(&mut p,&mut q,0,1,negative(7));
    pair(&mut p,&mut q,0,5,r(51));
    pair(&mut p,&mut q,0,6,r(53));
    let good=p.disequalities[0][&5].clone();
    let wrong=p.disequalities[0][&6].clone();
    p.disequalities[5].remove(&0);
    assert!(p.disequal_class_representatives(t(0)).is_err());
    assert!(p.canonical_disequalities().is_err());
    p.disequalities[0].insert(5,wrong.clone());
    p.disequalities[5].insert(0,wrong);
    assert!(p.separation_witnesses(t(0),t(5)).is_err());
    assert!(p.minimum_separation_witness(t(0),t(5)).is_err());
    assert!(p.validate().is_err());
    let cut=p.snapshot();
    let owners=p.disequalities.clone();
    let old_stats=p.virtual_adjacency_stats();
    // The failing edge isn't incident on either merge argument. Conversion must
    // discover it before publishing even the first staged adjacency or undo entry.
    assert!(p.merge(t(2),t(4),r(305)).is_err());
    assert_eq!(p.snapshot(),cut);
    assert_eq!(p.disequalities,owners);
    assert_eq!(p.virtual_adjacency_stats(),old_stats);
    p.disequalities[0].insert(5,good.clone());p.disequalities[5].insert(0,good);
    assert_eq!(p.virtual_adjacency_stats().live_pairs,1);
    check_small(&p,&q);
}

#[test]
fn virtual_adjacency_existing_partition_and_cross_token_capacity_epoch() {
    let (mut p,mut q)=(Partition::new(9).unwrap(),Partition::new(9).unwrap());
    // Existing nonsingleton and ordinary incidences; only the four group members must be singletons.
    assert_eq!(p.merge(t(5),t(6),r(91)),q.merge(t(5),t(6),r(91)));
    pair(&mut p,&mut q,1,6,r(77));
    let before_group=(p.snapshot(),q.snapshot());
    assert!(p.register_group_rows_for_virtual_test(&[t(3),t(0),t(2),t(1)],&[50,7,30],false,true));
    assert!(!p.set_virtual_plain_limit_for_test(0));
    assert!(p.set_virtual_plain_limit_for_test(1));
    let mut a=p.checked_separation_batch().unwrap();
    let mut b=p.checked_separation_batch().unwrap();
    assert_eq!(p.separate_in_checked_batch(t(0),t(3),negative(50),&mut a),q.separate(t(0),t(3),negative(50)));
    // Synchronize two independent tokens to the same virtual state, without changing that state.
    assert_eq!(p.separate_in_checked_batch(t(3),t(0),negative(50),&mut b),Ok(SeparationOutcome::AlreadyPresent));
    let stale_epoch=b.epoch;
    let epoch=a.epoch;
    assert_eq!(p.separate_in_checked_batch(t(0),t(7),r(93),&mut a),q.separate(t(0),t(7),r(93)));
    assert_eq!(p.virtual_adjacency_stats().capacity_flushes,1);
    assert!(a.epoch>epoch,"in-flight token retained validation across representation change");
    assert_eq!(p.separate_in_checked_batch(t(1),t(8),r(95),&mut b),q.separate(t(1),t(8),r(95)));
    assert!(b.epoch>stale_epoch);
    check_small(&p,&q);
    assert_eq!(p.rollback(before_group.0),q.rollback(before_group.1));
    assert_eq!(p.disequal_class_representatives(t(6)),Ok(vec![t(1)]));
    check_small(&p,&q);
}

#[test]
fn virtual_adjacency_209_prefix_and_adversarial_late_merge_materializes() {
    let n=209u32;
    let members:Vec<_>=(0..n).map(|i|(i*41+23)%n).collect();
    let bases:Vec<_>=(0..n-1).map(|i|301+i*(n+3)).collect();
    let (mut p,mut q)=setup(n as usize+2,&members,&bases,false,true);
    let mut a=p.checked_separation_batch().unwrap();
    let mut b=q.checked_separation_batch().unwrap();
    // In debug mode Partition performs full invariant checks on every insertion;
    // the full native release gate still always executes all 21,736 insertions.
    let rows=if cfg!(debug_assertions){1}else{n as usize-1};
    let mut count=0;
    for i in 0..rows {
        for j in i+1..n as usize {
            let (l,h)=(members[i].min(members[j]),members[i].max(members[j]));
            let why=negative(bases[i]+(j-i-1) as u32);
            let v=p.separate_in_checked_batch(t(l),t(h),why,&mut a);
            assert_eq!(v,q.separate_in_checked_batch(t(l),t(h),why,&mut b));
            assert_eq!(v,Ok(SeparationOutcome::Added{relation_was_known:false}));
            count+=1;
            if j==i+1 || j==n as usize-1 {
                assert_eq!(p.minimum_separation_witness(t(h),t(l)).unwrap(),
                           Some((SeparationRecord{left:t(l),right:t(h),reason:why},false)));
                if j+1<n as usize {
                    assert_eq!(p.relation(t(members[i]),t(members[j+1])),Ok(Relation::Unknown));
                }
            }
        }
    }
    if !cfg!(debug_assertions){assert_eq!(count,21_736);}
    p.finish_group_rows();
    assert_eq!(p.virtual_adjacency_stats().live_pairs,count);
    assert_eq!(p.physical_adjacency_incidences(),0);
    assert_eq!(p.disequality_edge_count().unwrap(),count);
    let cut=(p.snapshot(),q.snapshot());
    // A successful alias to an outsider forces conversion; a conflicting clique merge would not.
    assert_eq!(p.merge(t(members[0]),t(n),r(999_991)),q.merge(t(members[0]),t(n),r(999_991)));
    let s=p.virtual_adjacency_stats();
    assert_eq!((s.live_pairs,s.skipped_pairs,s.peak_pairs,s.materialized_pairs,s.merge_flushes),(0,count,count,count,1));
    assert_eq!(p.physical_adjacency_incidences(),2*count);
    assert_eq!(p.disequal_class_representatives(t(n)),q.disequal_class_representatives(t(n)));
    assert_eq!(p.merge(t(n),t(members[1]),r(999_993)),q.merge(t(n),t(members[1]),r(999_993)));
    assert_eq!(p.rollback(cut.0),q.rollback(cut.1));
    assert_eq!(p.virtual_adjacency_stats().materializations,1);
    check(&p,&q);
}

// Appended inside the frozen virtual_adjacency_tests module, never a release item.
fn r2_merge(p: &mut Partition, q: &mut Partition, a:u32, b:u32, why:u64) {
    let got = p.merge(t(a),t(b),r(why));
    assert_eq!(got,q.merge(t(a),t(b),r(why)));
    assert!(matches!(got,Ok(MergeOutcome::Merged{..})));
}

fn r2_history(emit:bool) -> Vec<(usize,usize,usize,usize)> {
    let (mut p,mut q)=setup(9,&[0,1,2,3],&[7,20,31],false,true);
    let empty=(p.snapshot(),q.snapshot());
    let (mut batch,mut control)=(p.checked_separation_batch().unwrap(),q.checked_separation_batch().unwrap());
    let mut states=Vec::new();
    let mut mark=|name:&str,p:&Partition,q:&Partition| {
        check_small(p,q);
        let s=p.virtual_adjacency_stats();
        let physical=(s.live_pairs,s.merge_flushes,s.materialized_pairs,p.physical_adjacency_incidences());
        states.push(physical);
        if emit {
            println!("R2_LOGICAL|{name}|{}|{}|{:?}|{:?}|{:?}|{:?}",p.snapshot().state_id,
                p.update_count(),p.canonical_classes().unwrap(),p.separation_records(),
                p.update_endpoints_since(0).unwrap(),p.merge_records());
            println!("R2_BACKING|{name}|{}|{}|{}|{}",physical.0,physical.1,physical.2,physical.3);
        }
    };
    macro_rules! insert { ($a:expr,$b:expr,$atom:expr) => {{
        let got=p.separate_in_checked_batch(t($a),t($b),negative($atom),&mut batch);
        assert_eq!(got,q.separate_in_checked_batch(t($a),t($b),negative($atom),&mut control));
        assert!(got.unwrap().changed());
    }}; }
    r2_merge(&mut p,&mut q,4,5,101); // before any row; keep the selected descriptor
    let before_rows=(p.snapshot(),q.snapshot());
    mark("before_rows",&p,&q);
    insert!(0,1,7);
    let prefix=(p.snapshot(),q.snapshot());
    r2_merge(&mut p,&mut q,5,6,103); // requested 5 is not the root of its class
    let lost=(p.snapshot(),q.snapshot());
    mark("after_outsiders",&p,&q);
    insert!(0,2,8); // intervening merge consumed an ID: this interrupted row cannot extend
    assert_eq!(p.proof_test_physical_ids_between(t(0),t(2)),1);
    insert!(1,2,20); insert!(1,3,21); // intact new row
    p.finish_group_rows();
    mark("before_member",&p,&q);
    r2_merge(&mut p,&mut q,7,3,105);
    mark("after_member",&p,&q);
    assert_eq!(p.minimum_separation_witness(t(7),t(1)).unwrap(),
        Some((SeparationRecord{left:t(1),right:t(3),reason:negative(21)},false)));
    let at=p.snapshot();
    let conflict=p.merge(t(1),t(7),r(107));
    assert_eq!(conflict,q.merge(t(1),t(7),r(107)));
    assert!(matches!(conflict,Err(PartitionError::Conflict(_))));
    assert_eq!(p.snapshot(),at);
    assert_eq!(p.rollback(prefix.0),q.rollback(prefix.1));
    mark("prefix",&p,&q);
    r2_merge(&mut p,&mut q,5,8,109);
    assert_eq!(p.rollback(lost.0),q.rollback(lost.1));
    assert_eq!(p.rollback(lost.0),Err(PartitionError::InvalidSnapshot(SnapshotError::DiscardedBranch)));
    assert_eq!(p.rollback(before_rows.0),q.rollback(before_rows.1));
    mark("rewind_to_outsiders",&p,&q);
    assert_eq!(p.rollback(empty.0),q.rollback(empty.1));
    mark("empty",&p,&q);
    states
}

#[test]
fn fallback_r2_logical_transcript() {
    r2_history(true); // replay this exact stream on both R1 and R2
}

#[test]
fn fallback_r2_defers_only_isolated_outsiders() {
    let states=r2_history(false);
    assert_eq!(&states[..4],&[(0,0,0,0),(1,0,0,0),(3,0,0,2),(0,1,3,8)]);
    assert_eq!(&states[4..],&[(0,1,3,2),(0,1,3,0),(0,1,3,0)]);
}

#[test]
fn component_members_flush_and_only_outsider_neighbors_remain_virtual() {
    for (a,b,adjacent) in [(3,8,false),(8,3,false),(2,3,false),(5,6,true),(6,5,true)] {
        let (mut p,mut q)=setup(10,&[0,1,2,3],&[7,20,31],false,true);
        pair(&mut p,&mut q,0,1,negative(7));
        if adjacent {
            r2_merge(&mut p,&mut q,4,5,101);
            pair(&mut p,&mut q,4,9,r(71));
            assert!(p.disequalities[5].is_empty() && !p.disequalities[4].is_empty());
        }
        let before=p.snapshot();
        assert_eq!(p.merge(t(0),t(1),r(81)),q.merge(t(0),t(1),r(81))); // conflict
        assert_eq!(p.merge(t(8),t(8),r(83)),q.merge(t(8),t(8),r(83))); // redundant
        assert_eq!(p.snapshot(),before);
        assert_eq!(p.virtual_adjacency_stats().live_pairs,1);
        r2_merge(&mut p,&mut q,a,b,85);
        let s=p.virtual_adjacency_stats();
        assert_eq!((s.live_pairs,s.merge_flushes,s.materialized_pairs),if adjacent {(1,0,0)} else {(0,1,1)});
        check_small(&p,&q);
    }
}

#[test]
fn fallback_r2_nonempty_rollback_still_flushes() {
    for rows in [false,true] {
        let (mut p,mut q)=setup(8,&[0,1,2,3],&[7,20,31],false,true);
        if rows { pair(&mut p,&mut q,0,1,negative(7)); }
        let keep=(p.snapshot(),q.snapshot());
        r2_merge(&mut p,&mut q,4,5,111);
        let lost=(p.snapshot(),q.snapshot());
        assert_eq!(p.rollback(lost.0),Ok(0));assert_eq!(p.virtual_adjacency_stats().materializations,0);
        assert_eq!(p.rollback(keep.1),Err(PartitionError::InvalidSnapshot(SnapshotError::ForeignPartition)));
        assert_eq!(p.rollback(keep.0),q.rollback(keep.1));
        let s=p.virtual_adjacency_stats();
        assert_eq!((s.rollback_flushes,s.merge_flushes,s.materialized_pairs,s.live_pairs),(1,0,usize::from(rows),0));
        assert_eq!(p.physical_adjacency_incidences(),2*usize::from(rows));
        r2_merge(&mut p,&mut q,6,7,113);
        assert_eq!(p.rollback(lost.0),q.rollback(lost.1));
        assert_eq!(p.rollback(lost.0),Err(PartitionError::InvalidSnapshot(SnapshotError::DiscardedBranch)));
        check_small(&p,&q);
    }
}

// Same-history driver for frozen R2 and the local component-merge treatment.
fn component_core(eq:&[ReasonId], neq:SeparationRecord)->bool {
    // Ground equality closure on the fixture's original premises, not the Partition.
    let mut classes=std::array::from_fn::<_,16,_>(|i|i);
    for id in eq {
        let (a,b)=match id.raw() {101=>(4,5),103=>(5,10),105=>(4,11),_=>return false};
        let (x,y)=(classes[a],classes[b]);
        for v in &mut classes {if *v==y {*v=x;}}
    }
    let (a,b)=match neq.reason.raw() {214=>(10,11),212=>(10,8),_=>return false};
    neq.left==t(a) && neq.right==t(b) && classes[a as usize]==classes[b as usize]
}

fn component_evidence(p:&mut Partition,q:&mut Partition,emit:bool) {
    let original=|a,b,k|SeparationRecord{left:t(a),right:t(b),reason:r(k)};
    let shared=vec![original(4,6,202),original(10,6,210),original(6,10,216)];
    let snap=p.snapshot();
    assert_eq!(p.separation_witnesses(t(5),t(6)).unwrap(),Some(shared.clone()),"shared-neighbor witness loss");
    assert_eq!(p.minimum_separation_witness(t(6),t(5)).unwrap(),Some((shared[0],false)));
    let c=p.merge(t(5),t(6),r(109));
    assert_eq!(c,q.merge(t(5),t(6),r(109)));
    assert!(matches!(c,Err(PartitionError::Conflict(Conflict::EqualityAgainstDisequality{separations,..})) if separations==shared));
    let c=p.merge(t(4),t(11),r(105));
    assert_eq!(c,q.merge(t(4),t(11),r(105)));
    let Err(PartitionError::Conflict(Conflict::EqualityAgainstDisequality{equality,separations}))=c
        else {panic!("missing source conflict")};
    assert_eq!((equality.left,equality.right,equality.reason),(t(4),t(11),r(105)));
    assert_eq!(separations,vec![original(10,11,214)]);
    let witness=separations[0];
    let mut premises=p.equality_reasons(equality.left,witness.left).unwrap().unwrap();
    assert_eq!(premises,vec![r(101),r(103)]);
    premises.push(equality.reason);
    assert!(component_core(&premises,witness));
    for k in 0..3 {let mut bad=premises.clone();bad.remove(k);assert!(!component_core(&bad,witness));}
    assert!(!component_core(&premises,original(10,8,212)));
    if emit {
        println!("COMPONENT_CORE|{:?}|{}|{}|{}",premises.iter().map(|x|x.raw()).collect::<Vec<_>>(),
                 witness.left.raw(),witness.right.raw(),witness.reason.raw());
    }
    assert_eq!(p.snapshot(),snap);
}

fn component_history(emit:bool, member_first:bool)->Vec<(usize,usize,usize,usize)> {
    let (mut p,mut q)=setup(16,&[0,1,2,3],&[7,20,31],false,true);
    let empty=(p.snapshot(),q.snapshot());
    let (mut token,mut plain)=(p.checked_separation_batch().unwrap(),q.checked_separation_batch().unwrap());
    let sep=|p:&mut Partition,q:&mut Partition,a,b,k,pt:&mut CheckedSeparationBatch,qt:&mut CheckedSeparationBatch|{
        let got=p.separate_in_checked_batch(t(a),t(b),k,pt);
        assert_eq!(got,q.separate_in_checked_batch(t(a),t(b),k,qt));assert!(got.unwrap().changed());
    };
    sep(&mut p,&mut q,0,1,negative(7),&mut token,&mut plain);
    for (a,b,k) in [(4,6,202),(4,7,204),(4,8,206),(4,9,208),
                     (10,6,210),(10,8,212),(10,11,214),(6,10,216)] {
        sep(&mut p,&mut q,a,b,r(k),&mut token,&mut plain);
    }
    let mut states=Vec::new();
    let mut mark=|name:&str,p:&Partition,q:&Partition|{
        check(p,q);
        for a in 0..16 {
            assert_eq!(p.disequal_class_representatives(t(a)),q.disequal_class_representatives(t(a)));
            for b in 0..16 {
                assert_eq!(p.relation(t(a),t(b)),q.relation(t(a),t(b)));
                assert_eq!(p.separation_witnesses(t(a),t(b)),q.separation_witnesses(t(a),t(b)));
            }
        }
        let v=p.virtual_adjacency_stats();
        states.push((v.live_pairs,v.merge_flushes,v.rollback_flushes,p.physical_adjacency_incidences()));
        if emit {
            println!("COMPONENT_LOGICAL|{name}|{}|{}|{:?}|{:?}|{:?}|{:?}",p.snapshot().state_id,p.next_state_id,
                p.canonical_classes().unwrap(),p.canonical_disequalities().unwrap(),
                p.update_endpoints_since(0).unwrap(),p.merge_records());
            println!("COMPONENT_BACKING|{name}|{}|{}|{}|{}",v.live_pairs,v.merge_flushes,v.rollback_flushes,
                     p.physical_adjacency_incidences());
        }
    };
    assert_eq!((p.disequalities[4].len(),p.disequalities[5].len()),(4,0));
    let first=(p.snapshot(),q.snapshot());let maps=p.disequalities[4..].to_vec();
    mark("seed",&p,&q);
    r2_merge(&mut p,&mut q,4,5,101);
    mark("four_zero",&p,&q);
    let second=(p.snapshot(),q.snapshot());let maps2=p.disequalities[4..].to_vec();
    assert_eq!((p.disequalities[4].len(),p.disequalities[10].len()),(4,3));
    let epoch=token.epoch;
    r2_merge(&mut p,&mut q,5,10,103); // alias 5 names root 4; neighbors 6 and 8 overlap
    let discarded=(p.snapshot(),q.snapshot());
    let Undo::Merge{kept,removed,kept_size,kept_minimum,kept_adjacency,removed_adjacency,record}
        =&p.trail.last().unwrap().undo else {panic!("missing merge undo")};
    assert_eq!((*kept,*removed,*kept_size,*kept_minimum),(4,10,2,t(4)));
    assert_eq!((kept_adjacency,removed_adjacency),(&maps2[0],&maps2[6]));
    assert_eq!((record.left,record.right,record.reason),(t(5),t(10),r(103)));
    component_evidence(&mut p,&mut q,emit);
    mark("overlap",&p,&q);
    sep(&mut p,&mut q,1,2,negative(20),&mut token,&mut plain);
    assert!(token.epoch>epoch && token.snapshot==p.snapshot());
    mark("after_checked_insert",&p,&q);
    if member_first { r2_merge(&mut p,&mut q,3,15,111); }
    else {
        let now=p.snapshot();
        assert_eq!(p.rollback(now),Ok(0));
        assert_eq!(p.rollback(q.snapshot()),Err(PartitionError::InvalidSnapshot(SnapshotError::ForeignPartition)));
        assert_eq!(p.snapshot(),now);
    }
    assert_eq!(p.rollback(second.0),q.rollback(second.1));
    assert_eq!(&p.disequalities[4..],maps2.as_slice(),"overlapping undo did not restore both old maps");
    mark("undo_overlap",&p,&q);
    assert_eq!(p.rollback(first.0),q.rollback(first.1));
    assert_eq!(&p.disequalities[4..],maps.as_slice());
    mark("undo_first",&p,&q);
    let epoch=token.epoch;
    sep(&mut p,&mut q,2,3,negative(31),&mut token,&mut plain);
    assert!(token.epoch>epoch && token.snapshot==p.snapshot());
    r2_merge(&mut p,&mut q,12,14,113);
    assert_eq!(p.rollback(discarded.0),q.rollback(discarded.1));
    assert_eq!(p.rollback(discarded.0),Err(PartitionError::InvalidSnapshot(SnapshotError::DiscardedBranch)));
    assert_eq!(p.rollback(empty.0),q.rollback(empty.1));
    mark("empty",&p,&q);
    states
}

#[test]
fn component_preflight_transcript() {
    component_history(true,false);
}

#[test]
fn component_preflight_overlap_and_undo() {
    for member in [false,true] {
        let s=component_history(false,member);
        assert_eq!(&s[..4],&[(1,0,0,16),(1,0,0,16),(1,0,0,16),(2,0,0,16)],"outsider retention");
        let (m,b)=if member {(1,0)}else{(0,1)};
        assert_eq!(&s[4..],&[(0,m,b,18),(0,m,b,18),(0,m,b,0)]);
    }
}

#[test]
fn component_preflight_degree_cap_counts_keys_on_both_sides() {
    for second in [31,32,33] {
        let (mut p,mut q)=setup(44,&[0,1,2,3],&[7,20,31],false,true);
        pair(&mut p,&mut q,0,1,negative(7));
        for n in 0..32 {pair(&mut p,&mut q,4,6+n,r(201+2*u64::from(n)));}
        for n in 0..second {pair(&mut p,&mut q,5,6+n,r(401+2*u64::from(n)));}
        // Counting witness IDs would exceed 64 even for the 63- and 64-key cases.
        for k in [701,703,705]{pair(&mut p,&mut q,6,4,r(k));}
        let snap=(p.snapshot(),q.snapshot());let raw=p.disequalities[4..].to_vec();
        r2_merge(&mut p,&mut q,5,4,801);
        let s=p.virtual_adjacency_stats();let flush=usize::from(32+second>64);
        assert_eq!((s.merge_flushes,s.live_pairs),(flush,1-flush),"64-key summed boundary");
        check(&p,&q);assert_eq!(p.rollback(snap.0),q.rollback(snap.1));
        assert_eq!(&p.disequalities[4..],raw.as_slice());check(&p,&q);
    }
    // At exactly 64 keys the last key of the second map still matters.
    let (mut p,mut q)=setup(72,&[68,69,70,71],&[7,20,31],false,true);
    pair(&mut p,&mut q,68,69,negative(7));
    for n in 2..34 {pair(&mut p,&mut q,0,n,r(201+2*u64::from(n)));}
    for n in 2..33 {pair(&mut p,&mut q,1,n,r(401+2*u64::from(n)));}
    pair(&mut p,&mut q,1,71,r(602));
    assert_eq!((p.disequalities[0].len(),p.disequalities[1].len()),(32,32));
    r2_merge(&mut p,&mut q,0,1,801);
    assert_eq!(p.virtual_adjacency_stats().merge_flushes,1,"64th key is selected");
    check(&p,&q);
}

#[test]
fn component_preflight_four_zero_before_first_virtual_row() {
    let (mut p,mut q)=setup(12,&[0,1,2,3],&[7,20,31],false,true);
    for n in 6..10 {pair(&mut p,&mut q,4,n,r(201+2*u64::from(n)));}
    assert_eq!((p.disequalities[4].len(),p.disequalities[5].len()),(4,0));
    let before=(p.snapshot(),q.snapshot());let outside=p.disequalities[4..].to_vec();
    r2_merge(&mut p,&mut q,5,4,401);
    assert_eq!(p.virtual_adjacency_stats().materializations,0,"descriptor retired before the first group row");
    pair(&mut p,&mut q,0,1,negative(7));
    assert_eq!((p.virtual_adjacency_stats().live_pairs,p.physical_adjacency_incidences()),(1,8));
    assert_eq!(p.rollback(before.0),q.rollback(before.1));
    assert_eq!(&p.disequalities[4..],outside.as_slice());
    assert_eq!(p.virtual_adjacency_stats().rollback_flushes,1);check(&p,&q);
}

#[test]
fn component_preflight_member_key_on_either_root() {
    for owner in [4,5,8] {
        let (mut p,mut q)=setup(24,&[20,21,22,23],&[7,20,31],false,true);
        pair(&mut p,&mut q,20,21,negative(7));
        r2_merge(&mut p,&mut q,4,14,501);r2_merge(&mut p,&mut q,5,15,503);
        pair(&mut p,&mut q,4,8,r(601));pair(&mut p,&mut q,5,9,r(603));
        pair(&mut p,&mut q,owner,23,r(605)); // selected key is last; in the third case it is two hops away
        let snap=(p.snapshot(),q.snapshot());
        r2_merge(&mut p,&mut q,15,14,507);
        let s=p.virtual_adjacency_stats();let flush=usize::from(owner!=8);
        assert_eq!((s.merge_flushes,s.live_pairs),(flush,1-flush),"one-hop member-key barrier");
        assert_eq!(p.rollback(snap.0),q.rollback(snap.1));check(&p,&q);
    }
    for (a,b) in [(2,6),(6,2),(2,3)] {
        let (mut p,mut q)=setup(8,&[0,1,2,3],&[7,20,31],false,true);
        pair(&mut p,&mut q,0,1,negative(7)); // both input roots have empty maps
        r2_merge(&mut p,&mut q,a,b,111);
        assert_eq!(p.virtual_adjacency_stats().merge_flushes,1,"direct member barrier");
        check(&p,&q);
    }
}

#[test]
fn component_preflight_corrupt_incidence_and_undo_are_rejected() {
    let (mut p,mut q)=setup(10,&[0,1,2,3],&[7,20,31],false,true);
    pair(&mut p,&mut q,0,1,negative(7));
    pair(&mut p,&mut q,4,6,r(31));pair(&mut p,&mut q,5,7,r(33));
    let original=p.disequalities.clone();let anchor=(p.snapshot(),q.snapshot());
    let stats=p.virtual_adjacency_stats();
    for symmetric in [false,true] {
        if symmetric {
            let id=*original[5][&7].iter().next().unwrap();
            p.disequalities[4].get_mut(&6).unwrap().insert(id);p.disequalities[6].get_mut(&4).unwrap().insert(id);
        } else {p.disequalities[6].remove(&4);}
        assert!(matches!(p.merge(t(4),t(5),r(35)),Err(PartitionError::InvariantViolation(_))));
        assert_eq!(p.snapshot(),anchor.0);assert_eq!(p.virtual_adjacency_stats(),stats);
        p.disequalities.clone_from(&original);
    }
    r2_merge(&mut p,&mut q,4,5,35);
    let joined=p.snapshot();let good=p.disequalities.clone();
    let bad=*good[4][&6].iter().next().unwrap();
    p.disequalities[4].get_mut(&7).unwrap().insert(bad);p.disequalities[7].get_mut(&4).unwrap().insert(bad);
    assert!(p.preflight_undo(&p.trail.last().unwrap().undo).is_err());
    assert_eq!(p.snapshot(),joined);
    p.disequalities=good;
    assert_eq!(p.rollback(anchor.0),q.rollback(anchor.1));
    assert_eq!(&p.disequalities[4..],&original[4..]);check(&p,&q);
}
