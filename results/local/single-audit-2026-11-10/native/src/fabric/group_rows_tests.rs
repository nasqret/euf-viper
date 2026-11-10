use super::*;

fn t(n:u32)->TermId {TermId::new(n)}
fn r(a:u32)->ReasonId {ReasonId::new(2*u64::from(a)+2)}
fn owners(s:GroupRowsStats, tracked:usize, plain:usize) {
    assert_eq!(s.tracked_live,tracked);
    let (compressed,shadow)=if s.representation_explicit{(0,tracked)}else{(tracked,0)};
    assert_eq!((s.compressed_live,s.shadow_live,s.explicit_len),(compressed,shadow,plain+shadow));
}
fn push(p:&mut Partition,a:u32,b:u32,atom:u32) {
    assert!(matches!(p.separate(t(a),t(b),r(atom)),Ok(SeparationOutcome::Added{..})))
}
fn eq_views(a:&Partition,b:&Partition) {
    assert!(a.validate().is_ok() && b.validate().is_ok());
    assert_eq!(a.separation_count(),b.separation_count());
    assert_eq!(a.separation_records(),b.separation_records());
    assert_eq!(a.canonical_disequalities(),b.canonical_disequalities());
    for i in 0..a.term_count() as u32 {for j in 0..a.term_count() as u32 {
        assert_eq!(a.minimum_separation_witness(t(i),t(j)),b.minimum_separation_witness(t(i),t(j)));
        assert_eq!(a.separation_witnesses(t(i),t(j)),b.separation_witnesses(t(i),t(j)));
    }}
}
#[test]
fn group_rows_mixed_orientation_interleaved_groups_and_conflict() {
    let mut p=Partition::new(9).unwrap();let mut control=Partition::new(9).unwrap();
    let terms=[t(4),t(1),t(6),t(2)];
    assert!(p.register_group_rows(&terms,&[19,0,31]));
    // Within a single row the position of the source anchor changes between left and right.
    for (a,b,atom) in [(1,4,19),(4,6,20),(2,4,21)] {
        assert!(p.group_rows_accepts(t(a),t(b),r(atom)));push(&mut p,a,b,atom);push(&mut control,a,b,atom);
    }
    assert!(p.register_group_rows(&[t(0),t(5)],&[12]));
    for (a,b,atom) in [(0,5,12),(1,6,0),(1,2,1),(2,6,31)] {
        push(&mut p,a,b,atom);push(&mut control,a,b,atom);
    }
    let s=p.group_rows_stats();owners(s,7,0);assert_eq!((s.groups,s.rows,s.tracked_peak),(2,4,7));
    assert_eq!((s.compressed_peak,s.shadow_peak),if s.representation_explicit{(0,7)}else{(7,0)});
    assert_eq!(p.group_rows_group_tracked_stats(),vec![(4,6),(2,1)]);
    assert_eq!(p.group_rows_group_stats(),if s.representation_explicit{vec![(4,0),(2,0)]}else{vec![(4,6),(2,1)]});
    assert_eq!(s.codec_heap_bytes,s.codec_header_width+s.group_capacity*s.group_width+s.row_capacity*s.row_width+
        s.atom_index_capacity*s.atom_index_width+s.run_capacity*s.run_width+s.member_capacity*s.member_width);
    assert_eq!(p.separate(t(4),t(1),r(19)).unwrap(),SeparationOutcome::AlreadyPresent);
    assert_eq!(p.merge(t(1),t(4),ReasonId::new(91)),control.merge(t(1),t(4),ReasonId::new(91)));
    p.finish_group_rows();assert!(!p.group_rows_has_atom(19));
    push(&mut p,6,7,88);push(&mut control,6,7,88);
    assert_eq!(p.merge(t(7),t(8),ReasonId::new(3)),control.merge(t(7),t(8),ReasonId::new(3)));
    eq_views(&p,&control);
}
#[test]
fn group_rows_partial_rollback_never_decodes_across_hole_or_reused_logical_position() {
    let mut p=Partition::new(6).unwrap();let mut c=Partition::new(6).unwrap();
    assert!(p.register_group_rows(&[t(0),t(1),t(2),t(3)],&[40,10,50]));
    let empty=p.snapshot();let ec=c.snapshot();
    push(&mut p,0,1,40);push(&mut c,0,1,40);let first=p.snapshot();let fc=c.snapshot();
    push(&mut p,0,2,41);push(&mut c,0,2,41);let discarded=p.snapshot();
    push(&mut p,0,3,42);push(&mut c,0,3,42);
    let old_id=p.trail.last().unwrap().state_id;
    p.rollback(first).unwrap();c.rollback(fc).unwrap();
    assert!(p.row_record(&old_id).is_none());owners(p.group_rows_stats(),1,0);
    assert!(!p.group_rows_accepts(t(0),t(2),r(41)));push(&mut p,0,2,41);push(&mut c,0,2,41);
    push(&mut p,0,3,42);push(&mut c,0,3,42);
    assert!(p.rollback(discarded).is_err());
    owners(p.group_rows_stats(),1,2);eq_views(&p,&c);
    p.rollback(empty).unwrap();c.rollback(ec).unwrap();assert_eq!(p.group_rows_stats().active_runs,0);
    for a in 1..4 {push(&mut p,0,a,39+a);push(&mut c,0,a,39+a);}
    assert!(p.trail.last().unwrap().state_id>old_id);eq_views(&p,&c);
    p.finish_group_rows();p.rollback(empty).unwrap();c.rollback(ec).unwrap();
    push(&mut p,0,1,40);push(&mut c,0,1,40);
    owners(p.group_rows_stats(),0,1);eq_views(&p,&c);
}
#[test]
fn group_rows_registration_refuses_overlap_duplicates_bounds_and_aliases_atomically() {
    let mut p=Partition::new(7).unwrap();
    assert!(!p.register_group_rows(&[t(1),t(1)],&[0]));
    assert!(!p.register_group_rows(&[t(1),t(7)],&[0]));
    assert!(!p.register_group_rows(&[t(1),t(2),t(3)],&[u32::MAX,0]));
    assert!(!p.register_group_rows(&[t(1),t(2),t(3)],&[9,10]));
    assert!(!p.register_group_rows(&[t(1),t(2)],&[]));
    assert_eq!(p.group_rows_stats().codec_heap_bytes,0);
    assert!(p.register_group_rows(&[t(0),t(1),t(2)],&[4,u32::MAX]));
    let before=p.group_rows_stats();
    for bad in [4,5,u32::MAX] {
        assert!(!p.register_group_rows(&[t(5),t(6)],&[bad]));assert_eq!(before,p.group_rows_stats());
    }
    assert!(p.group_rows_accepts(t(1),t(2),r(u32::MAX)));push(&mut p,1,2,u32::MAX);
    let s=p.snapshot();p.merge(t(0),t(6),ReasonId::new(17)).unwrap();
    assert!(!p.register_group_rows(&[t(0),t(5)],&[18]));
    assert!(!p.group_rows_accepts(t(0),t(1),r(4)));push(&mut p,0,1,4);
    assert_eq!(p.group_rows_stats().fallback_identity,1);p.rollback(s).unwrap();
    assert!(p.group_rows_accepts(t(0),t(1),r(4)));
    p.finish_group_rows();assert!(!p.register_group_rows(&[t(5),t(6)],&[11]));
    let mut empty=Partition::new(2).unwrap();empty.finish_group_rows();
    assert!(!empty.register_group_rows(&[t(0),t(1)],&[1]));
}
#[test]
fn group_rows_unregistered_wrong_sign_backwards_gap_and_multireason_are_explicit() {
    let mut p=Partition::new(7).unwrap();let mut c=Partition::new(7).unwrap();
    assert!(p.register_group_rows(&[t(0),t(1),t(2),t(3)],&[0,5,8]));
    for (left,right,reason) in [(0,1,r(0)),(5,6,ReasonId::new(3)),(0,2,r(1)),(3,0,r(2)),
                                (1,4,r(5)),(1,2,r(5)),(1,2,r(19)),(1,5,ReasonId::MIN)] {
        assert_eq!(p.separate(t(left),t(right),reason),c.separate(t(left),t(right),reason));eq_views(&p,&c);
    }
    let a=p.group_rows_stats();
    owners(a,2,6);assert_eq!(a.fallback_inserts,6);
    assert_eq!((a.fallback_identity,a.fallback_sequence,a.fallback_unregistered),(2,1,3));
}
#[test]
fn group_rows_all_three_member_permutations_and_cutoffs() {
    for terms in [[0,1,2],[0,2,1],[1,0,2],[1,2,0],[2,0,1],[2,1,0]] {
        for cut in 0..=3 {
            let mut p=Partition::new(4).unwrap();let mut c=Partition::new(4).unwrap();
            assert!(p.register_group_rows(&terms.map(t),&[7,2]));
            let mut checkpoints=vec![(p.snapshot(),c.snapshot())];
            for (i,j,atom) in [(0,1,7),(0,2,8),(1,2,2)] {
                let (a,b)=(terms[i].min(terms[j]),terms[i].max(terms[j]));
                push(&mut p,a,b,atom);push(&mut c,a,b,atom);checkpoints.push((p.snapshot(),c.snapshot()));
            }
            owners(p.group_rows_stats(),3,0);
            p.rollback(checkpoints[cut].0).unwrap();c.rollback(checkpoints[cut].1).unwrap();eq_views(&p,&c);
        }
    }
}
