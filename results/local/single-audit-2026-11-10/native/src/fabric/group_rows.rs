//! A live interval exists only after its records have actually been committed.
use super::{EdgeId, ReasonId, SeparationRecord, TermId};
use std::mem::size_of;

#[derive(Debug,Default,Clone,Copy,PartialEq,Eq)]
pub(crate) struct GroupRowsStats {
    pub(crate) representation_explicit:bool,
    pub(crate) tracked_live:usize, pub(crate) tracked_peak:usize, pub(crate) tracked_inserts:usize,
    pub(crate) shadow_live:usize, pub(crate) shadow_peak:usize, pub(crate) shadow_inserts:usize,
    pub(crate) groups:usize, pub(crate) rows:usize,
    pub(crate) compressed_live:usize, pub(crate) compressed_peak:usize, pub(crate) compressed_inserts:usize,
    pub(crate) fallback_inserts:usize, pub(crate) fallback_identity:usize,
    pub(crate) fallback_sequence:usize, pub(crate) fallback_unregistered:usize,
    pub(crate) explicit_len:usize, pub(crate) explicit_capacity:usize,
    pub(crate) explicit_backing_bytes:Option<usize>, pub(crate) codec_heap_bytes:usize,
    pub(crate) partition_slot_bytes:usize,
    pub(crate) group_capacity:usize, pub(crate) row_capacity:usize, pub(crate) atom_index_capacity:usize,
    pub(crate) run_capacity:usize, pub(crate) active_runs:usize, pub(crate) member_capacity:usize,
    pub(crate) codec_header_width:usize, pub(crate) group_width:usize, pub(crate) row_width:usize,
    pub(crate) atom_index_width:usize, pub(crate) run_width:usize, pub(crate) member_width:usize,
}
#[derive(Debug)]
struct Group { terms:Vec<TermId>, live:usize }
#[derive(Clone,Copy,Debug)]
struct Spec { base:u32, group:u32, pos:u32, len:u32, first:EdgeId }
#[derive(Clone,Copy,Debug)]
struct AtomIndex { base:u32, row:u32 }
#[derive(Clone,Copy,Debug)]
struct Run { first:EdgeId, row:u32, len:u32 }
#[derive(Debug,Default)]
pub(super) struct Codec {
    groups:Vec<Group>, specs:Vec<Spec>, atoms:Vec<AtomIndex>, runs:Vec<Run>,
    sealed:bool, explicit:bool, live:usize, peak:usize, inserted:usize,
    identity:usize, sequence:usize, unregistered:usize,
}
// Fixed-size boxed array permits fallible construction without unsafe or Box::try_new.
pub(super) type Owner=Box<[Codec;1]>;
#[derive(Debug,Default)]
pub(super) struct Slot { codec:Option<Owner>, closed_empty:bool }
impl Slot {
    #[inline] pub(super) fn get(&self)->Option<&Codec>{self.codec.as_ref().map(|b|&b[0])}
    #[inline] pub(super) fn get_mut(&mut self)->Option<&mut Codec>{self.codec.as_mut().map(|b|&mut b[0])}
    pub(super) fn register(&mut self,terms:&[TermId],bases:&[u32],n:usize)->bool {
        self.register_mode(terms,bases,n,None)
    }
    pub(super) fn seal(&mut self){if let Some(c)=self.get_mut(){c.seal()}else{self.closed_empty=true}}
}

#[derive(Clone,Copy)]
enum Check {New(u32),Extend,Identity,Sequence,Unregistered}
fn negative_atom(reason:ReasonId)->Option<u32> {
    let id=reason.raw();
    if id&1!=0{return None}
    u32::try_from((id/2).checked_sub(1)?).ok()
}
fn heap<T>(v:&Vec<T>)->usize {v.capacity()*size_of::<T>()}
impl Codec {
    fn owner(self)->Option<Owner> {
        let mut v=Vec::new();v.try_reserve_exact(1).ok()?;v.push(self);
        v.into_boxed_slice().try_into().ok()
    }
    pub(super) fn register(&mut self,terms:&[TermId],bases:&[u32],term_count:usize)->bool {
        if self.sealed || terms.len()<2 || terms.len()-1!=bases.len() || terms.len()>u32::MAX as usize ||
            self.specs.len().checked_add(bases.len()).is_none_or(|n|n>u32::MAX as usize) ||
            self.groups.len()>=u32::MAX as usize {return false}
        let mut members=Vec::new();
        if members.try_reserve_exact(terms.len()).is_err(){return false}
        members.extend_from_slice(terms);
        if members.iter().any(|v|v.index()>=term_count){return false}
        // Reuse the eventual member allocation as a temporary uniqueness check.
        members.sort_unstable();
        if members.windows(2).any(|w|w[0]==w[1]) {return false}
        members.copy_from_slice(terms);
        let mut intervals=Vec::new();
        if intervals.try_reserve_exact(bases.len()).is_err(){return false}
        for (i,&base) in bases.iter().enumerate() {
            let len=(bases.len()-i) as u32;
            let Some(last)=base.checked_add(len-1) else{return false};
            intervals.push((base,last));
        }
        intervals.sort_unstable();
        if intervals.windows(2).any(|w|w[0].1>=w[1].0){return false}
        for &(base,last) in &intervals {
            let ix=self.atoms.partition_point(|s|s.base<=last);
            if ix!=0 {
                let s=self.specs[self.atoms[ix-1].row as usize];
                if u64::from(base) < u64::from(s.base)+u64::from(s.len){return false}
            }
        }
        let new_total=self.specs.len()+bases.len();
        if self.groups.try_reserve(1).is_err() || self.specs.try_reserve_exact(bases.len()).is_err() ||
           self.atoms.try_reserve_exact(bases.len()).is_err() ||
           self.runs.try_reserve_exact(new_total-self.runs.len()).is_err(){return false}
        let group=self.groups.len() as u32;
        for (i,&base) in bases.iter().enumerate() {
            let row=self.specs.len() as u32;
            self.atoms.push(AtomIndex{base,row});
            self.specs.push(Spec{base,group,pos:i as u32,len:(bases.len()-i) as u32,first:0});
        }
        self.atoms.sort_unstable_by_key(|r|r.base);
        self.groups.push(Group{terms:members,live:0});
        true
    }
    #[inline] fn spec(&self,atom:u32)->Option<u32> {
        let idx=self.atoms.partition_point(|r|r.base<=atom).checked_sub(1)?;
        let ix=self.atoms[idx];(atom-ix.base<self.specs[ix.row as usize].len).then_some(ix.row)
    }
    pub(super) fn has(&self,atom:u32)->bool {!self.sealed && self.spec(atom).is_some()}
    fn endpoints(&self,s:Spec,offset:u32)->(TermId,TermId) {
        let members=&self.groups[s.group as usize].terms;
        let (a,b)=(members[s.pos as usize],members[s.pos as usize+1+offset as usize]);
        if a<b {(a,b)}else{(b,a)}
    }
    fn check(&self,id:EdgeId,rec:SeparationRecord,singletons:bool)->Check {
        let Some(atom)=negative_atom(rec.reason) else{return Check::Unregistered};
        let Some(row)=self.spec(atom) else{return Check::Unregistered};
        let s=self.specs[row as usize];let pos=atom-s.base;
        if !singletons || self.endpoints(s,pos)!=(rec.left,rec.right){return Check::Identity}
        if s.first==0 && pos==0 && id!=0 && self.runs.last().is_none_or(|r|id>r.first && id-r.first>=u64::from(r.len)){
            return Check::New(row)
        }
        if let Some(r)=self.runs.last(){
            if r.row==row && pos==r.len && r.len<s.len && r.first.checked_add(u64::from(r.len))==Some(id){
                return Check::Extend
            }
        }
        Check::Sequence
    }
    pub(super) fn accepts(&self,id:EdgeId,rec:SeparationRecord,singletons:bool)->bool{
        !self.sealed && matches!(self.check(id,rec,singletons),Check::New(_)|Check::Extend)
    }
    pub(super) fn commit(&mut self,id:EdgeId,rec:SeparationRecord,singletons:bool)->bool {
        if self.sealed{return false}
        let row=match self.check(id,rec,singletons) {
            Check::New(row)=>{
                self.specs[row as usize].first=id;
                self.runs.push(Run{first:id,row,len:1});row
            }
            Check::Extend=>{let run=self.runs.last_mut().unwrap();run.len+=1;run.row}
            Check::Identity=>{self.identity+=1;return false}
            Check::Sequence=>{self.sequence+=1;return false}
            Check::Unregistered=>{self.unregistered+=1;return false}
        };
        self.groups[self.specs[row as usize].group as usize].live+=1;
        self.live+=1;self.peak=self.peak.max(self.live);self.inserted+=1;true
    }
    pub(super) fn seal(&mut self){self.sealed=true}
    #[inline] fn run(&self,id:EdgeId)->Option<Run>{
        let end=self.runs.last()?;
        let r=if id>=end.first {*end} else {
            *self.runs.get(self.runs.partition_point(|r|r.first<=id).checked_sub(1)?)?
        };
        (id-r.first<u64::from(r.len)).then_some(r)
    }
    #[inline] pub(super) fn contains(&self,id:EdgeId)->bool {self.run(id).is_some()}
    fn record(&self,run:Run,delta:u32)->SeparationRecord{
        let s=self.specs[run.row as usize];
        let (left,right)=self.endpoints(s,delta);
        SeparationRecord{left,right,reason:ReasonId::new(2*(u64::from(s.base)+u64::from(delta))+2)}
    }
    pub(super) fn get(&self,id:EdgeId)->Option<SeparationRecord>{
        self.run(id).map(|r|self.record(r,(id-r.first) as u32))
    }
    pub(super) fn entries(&self)->impl Iterator<Item=(EdgeId,SeparationRecord)>+'_ {
        self.runs.iter().copied().flat_map(move |r|(0..r.len).map(move |d|(r.first+u64::from(d),self.record(r,d))))
    }
    pub(super) fn can_undo(&self,id:EdgeId)->bool{
        self.run(id).is_none_or(|r|self.runs.last().is_some_and(|s|s.first==r.first) &&
                               id-r.first==u64::from(r.len-1))
    }
    pub(super) fn remove(&mut self,id:EdgeId)->bool{
        // Preflight checked original record and stack-tail identity before any mutation.
        let Some(r)=self.runs.last_mut() else{return false};
        if id<r.first || id-r.first!=u64::from(r.len-1){return false}
        let s=&mut self.specs[r.row as usize];
        self.groups[s.group as usize].live-=1;self.live-=1;r.len-=1;
        if r.len==0 {s.first=0;self.runs.pop();}
        true
    }
    pub(super) fn live(&self)->usize{self.live}
    pub(super) fn group_stats(&self)->Vec<(usize,usize)>{
        self.groups.iter().map(|g|(g.terms.len(),if self.explicit{0}else{g.live})).collect()
    }
    pub(super) fn add_stats(&self,s:&mut GroupRowsStats) {
        s.groups=self.groups.len();s.rows=self.specs.len();s.representation_explicit=self.explicit;
        (s.tracked_live,s.tracked_peak,s.tracked_inserts)=(self.live,self.peak,self.inserted);
        if self.explicit {
            (s.shadow_live,s.shadow_peak,s.shadow_inserts)=(self.live,self.peak,self.inserted);
        }else{
            (s.compressed_live,s.compressed_peak,s.compressed_inserts)=(self.live,self.peak,self.inserted);
        }
        s.fallback_identity=self.identity;s.fallback_sequence=self.sequence;
        s.fallback_unregistered=self.unregistered;s.fallback_inserts=self.identity+self.sequence+self.unregistered;
        // Requested payload for the live Box and actual Vec capacities, not whole-process heap/RSS.
        s.group_capacity=self.groups.capacity();s.row_capacity=self.specs.capacity();s.atom_index_capacity=self.atoms.capacity();
        s.run_capacity=self.runs.capacity();s.active_runs=self.runs.len();s.member_capacity=self.groups.iter().map(|g|g.terms.capacity()).sum();
        s.codec_header_width=size_of::<Self>();s.group_width=size_of::<Group>();s.row_width=size_of::<Spec>();
        s.atom_index_width=size_of::<AtomIndex>();s.run_width=size_of::<Run>();s.member_width=size_of::<TermId>();
        s.codec_heap_bytes=size_of::<Self>()+heap(&self.groups)+heap(&self.specs)+heap(&self.atoms)+heap(&self.runs)
            +self.groups.iter().map(|g|heap(&g.terms)).sum::<usize>();
    }
}

include!("row_representation.rs");
