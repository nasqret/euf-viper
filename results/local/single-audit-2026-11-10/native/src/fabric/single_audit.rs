//! Selected-partition, counter-only observer. No timers, per-ID writes, or solver shortcuts.
use super::*;
use std::fs::{File, OpenOptions};
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

const MAX_TERMS_OBSERVED:usize=1<<20;
const NAMES:[&str;25]=[
    "target_calls","target_ok","target_errors","empty_roots","nonempty_roots","neighbors",
    "first_physical","second_physical","second_virtual","duplicated_physical","id_join_errors",
    "impact_calls","impact_seed","impact_neighbor","impact_seed_repeat","impact_neighbor_repeat",
    "impact_calls_mixed","impact_seed_mixed","impact_neighbor_mixed","impact_seed_repeat_mixed","impact_neighbor_repeat_mixed",
    "batch_hits","batch_misses","batch_hits_mixed","batch_misses_mixed",
];
#[derive(Debug,Default,Copy,Clone)]
struct Phase([u64;25]);
impl Phase{
    fn put(&mut self,i:usize,n:u64){self.0[i]=self.0[i].checked_add(n).expect("single-audit counter overflow");}
    fn consistent(&self)->bool{
        let a=self.0;
        a[0]==a[1]+a[2] && a[2]==0 && a[1]==a[3]+a[4] && a[4]<=a[5] &&
            a[5]<=a[7]+a[8] && a[6]==a[7] && a[7]==a[9] && a[10]==0 &&
            a[14]<=a[12] && a[15]<=a[13] && a[19]<=a[17] && a[20]<=a[18] &&
            (11..16).all(|i|a[i+5]<=a[i]) && a[23]<=a[21] && a[24]<=a[22] && a[18]<=a[1]
    }
    #[cfg(feature="fabric")]
    fn json(&self)->serde_json::Value{
        serde_json::Value::Object(NAMES.into_iter().zip(self.0).map(|(k,v)|(k.into(),v.into())).collect())
    }
}
#[derive(Default)]
pub(super) struct Walk {
    pub(super) first:u64, pub(super) neighbors:u64,
    second:u64, virtuals:u64, duplicate:u64, join_errors:u64,
}
impl Walk {
    #[inline] pub(super) fn second(&mut self,id:EdgeId,virt:Option<EdgeId>,confirmed:&mut Option<std::collections::btree_set::Iter<'_,EdgeId>>){
        if Some(id)==virt{self.virtuals+=1;return}
        self.second+=1;
        if confirmed.as_mut().and_then(|it|it.next().copied())==Some(id){self.duplicate+=1}else{self.join_errors+=1}
    }
    #[inline] pub(super) fn end_pair(&mut self,confirmed:Option<std::collections::btree_set::Iter<'_,EdgeId>>){
        if confirmed.is_some_and(|it|it.len()!=0){self.join_errors+=1}
    }
}
#[derive(Debug,Default)]
struct State {
    p:[Phase;2],post:bool,singletons:bool,fixed_live:usize,bad:bool,
}
#[derive(Debug)]
struct Seen { epoch:u32, marks:Vec<u32> }
#[derive(Debug)]
pub(super) struct Observer {
    id:u64,n:usize,members:Vec<TermId>,bases:Vec<u32>,file:File,
    state:Mutex<State>,seen:Mutex<Seen>,
}
impl Observer{
    fn new(p:&Partition,members:&[TermId],bases:&[u32],file:File)->Self{
        assert!((2..=256).contains(&members.len()) && members.len()==bases.len()+1 &&
            p.term_count()<=MAX_TERMS_OBSERVED && members.iter().all(|&t|p.row_singleton(t) && p.virtual_member(t.index())),
            "single-audit: unbound/oversized selected group");
        Self{id:p.partition_id,n:p.term_count(),members:members.to_vec(),bases:bases.to_vec(),file,
            state:Mutex::default(),seen:Mutex::new(Seen{epoch:0,marks:vec![0;p.term_count()]})}
    }
    fn add(&self,body:impl FnOnce(&mut Phase)){
        let mut s=self.state.lock().unwrap();let ix=usize::from(s.post);body(&mut s.p[ix])
    }
    pub(super) fn target(&self,w:Walk,result:&PartitionResult<(usize,usize)>){
        self.add(|p|{
            p.put(0,1);
            match result{
                Ok((degree,_))=>{
                    p.put(1,1);p.put(if *degree==0{3}else{4},1);
                    p.put(10,u64::from(*degree as u64!=w.neighbors));
                }
                Err(_)=>p.put(2,1),
            }
            for (i,n) in [w.neighbors,w.first,w.second,w.virtuals,w.duplicate,w.join_errors].into_iter().enumerate(){p.put(i+5,n)}
        })
    }
    pub(super) fn batch(&self,hit:bool,mixed:bool){
        self.add(|p|{let i=if hit{21}else{22};p.put(i,1);if mixed{p.put(i+2,1)}})
    }
}

pub(crate) struct Impact<'a> {
    owner:&'a Observer, seen:MutexGuard<'a,Seen>, mixed:bool, local:[u64;4],
}
impl Impact<'_> {
    // Same immutable partition for the entire scope; the key is a physical root, not its minimum.
    pub(super) fn success(&mut self,root:usize,neighbor:bool){
        let k=usize::from(neighbor);
        self.local[k]+=1;
        let epoch=self.seen.epoch;let mark=&mut self.seen.marks[root];
        if *mark==epoch{self.local[k+2]+=1}else{*mark=epoch}
    }
}
impl Drop for Impact<'_>{
    fn drop(&mut self){
        self.owner.add(|p|{
            p.put(11,1);if self.mixed{p.put(16,1)}
            for (i,n) in self.local.into_iter().enumerate(){p.put(12+i,n);if self.mixed{p.put(17+i,n)}}
        });
    }
}

impl Partition{
    pub(crate) fn single_arm(&self,members:&[TermId],bases:&[u32],checked:bool){
        let Some(path)=std::env::var_os("VPR_SINGLE_AUDIT").filter(|s|!s.is_empty()) else{return};
        let path=PathBuf::from(path);
        assert!(path.is_absolute() && checked && self.virtual_rows.active() && self.group_rows_stats().groups==1,
            "single-audit requires absolute path and verified compact, globally checked registration");
        let file=OpenOptions::new().write(true).create_new(true).open(path).expect("fresh single audit output");
        assert!(self.single_audit.set(Box::new(Observer::new(self,members,bases,file))).is_ok(),"duplicate single audit");
    }
    pub(crate) fn single_fixed(&self){
        if let Some(o)=self.single_audit.get(){
            let mut s=o.state.lock().unwrap();s.bad|=s.post;s.post=true;
            s.singletons=o.members.iter().all(|&t|self.row_singleton(t));s.fixed_live=self.virtual_adjacency_stats().live_pairs;
        }
    }
    pub(crate) fn single_impact(&self)->Option<Impact<'_>>{
        let o=self.single_audit.get()?;
        let mut seen=o.seen.try_lock().expect("overlapping impact scopes on selected partition");
        if let Some(n)=seen.epoch.checked_add(1){seen.epoch=n}else{seen.marks.fill(0);seen.epoch=1}
        Some(Impact{owner:o,seen,mixed:self.has_virtual_adjacency(),local:[0;4]})
    }
    pub(crate) fn single_terminal(&self,outcome:&str){
        let Some(o)=self.single_audit.get() else{return};
        #[cfg(not(feature="fabric"))]
        { let _=o;panic!("named single-audit requires fabric: {outcome}") }
        #[cfg(feature="fabric")]
        {
            use serde_json::json;
            use std::io::Write;
            let s=o.state.lock().unwrap();let v=self.virtual_adjacency_stats();
            let mut errors=Vec::new();
            if o.id!=self.partition_id||o.n!=self.term_count()||s.bad||!s.post||!s.singletons{
                errors.push("selected partition or fixed boundary mismatch")
            }
            if !s.p.iter().all(Phase::consistent){errors.push("audit or impact conservation")}
            if !matches!(outcome,"sat"|"unsat"){errors.push("native did not finish normally")}
            let doc=json!({"schema":"single-audit-v1","pid":std::process::id(),"complete":errors.is_empty(),"errors":errors,
                "partition_id":o.id,"term_count":o.n,"member_terms":o.members.iter().map(|t|t.index()).collect::<Vec<_>>(),
                "row_atoms":o.bases,"arity":o.members.len(),"full_group_pairs":o.members.len()*(o.members.len()-1)/2,
                "fixed_all_singleton":s.singletons,"fixed_live_pairs":s.fixed_live,"terminal_live_pairs":v.live_pairs,
                "terminal_materialized_pairs":v.materialized_pairs,"terminal_outcome":outcome,"fixed":s.p[0].json(),"post":s.p[1].json()});
            let mut file=&o.file;
            serde_json::to_writer(&mut file,&doc).expect("write single-audit");
            file.write_all(b"\n").and_then(|_|file.sync_all()).expect("sync single-audit");
        }
    }
}

#[cfg(test)]
#[path="single_audit_tests.rs"] mod single_audit_tests;
