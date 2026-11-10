//! The witness codec and original trail remain authoritative. Only the two
//! adjacency inserts of a committed fresh singleton pair may be represented here.
use super::*;
use std::collections::{btree_map, btree_set};
use std::iter::Peekable;

const MAX_MEMBERS: usize = 256;
const MAX_PLAIN: usize = 65_536;
fn invalid(message: &'static str) -> PartitionError { PartitionError::InvariantViolation(message) }

#[derive(Debug,Default,Clone,Copy,PartialEq,Eq)]
pub(crate) struct VirtualAdjacencyStats {
    pub(crate) skipped_pairs: usize, pub(crate) live_pairs: usize, pub(crate) peak_pairs: usize,
    pub(crate) materialized_pairs: usize, pub(crate) materializations: usize,
    pub(crate) merge_flushes: usize, pub(crate) rollback_flushes: usize, pub(crate) capacity_flushes: usize,
}

#[derive(Debug)]
struct Row { base:u32, first:EdgeId, live:usize }
#[derive(Debug)]
struct Group {
    terms: Vec<TermId>, sorted: Vec<(usize,usize)>, rows: Vec<Row>,
    plain: usize, limit: usize,
}
#[derive(Debug)]
struct Owner { group: Option<Group>, stats: VirtualAdjacencyStats }
#[derive(Debug,Default)]
pub(super) struct Slot(Option<Box<[Owner;1]>>);
pub(super) enum Trigger { Merge, Rollback, Capacity }

impl Group {
    fn new(p:&Partition, terms:&[TermId], bases:&[u32])->Option<Self>{
        if !(2..=MAX_MEMBERS).contains(&terms.len()) || bases.len()!=terms.len()-1{return None}
        let mut members=Vec::new(); members.try_reserve_exact(terms.len()).ok()?;
        let mut sorted=Vec::new(); sorted.try_reserve_exact(terms.len()).ok()?;
        let mut rows=Vec::new(); rows.try_reserve_exact(bases.len()).ok()?;
        let mut plain=0usize;
        for (i,&t) in terms.iter().enumerate(){
            if !p.row_singleton(t){return None}
            for ids in p.disequalities[t.index()].values(){
                plain=plain.checked_add(ids.len())?;
                if plain>MAX_PLAIN{return None}
            }
            sorted.push((t.index(),i)); members.push(t);
            if let Some(&base)=bases.get(i){
                // Codec::register already verified disjoint atom intervals. Its
                // partition API does not require them to be in source-row order.
                base.checked_add((terms.len()-2-i) as u32)?;
                rows.push(Row{base,first:0,live:0});
            }
        }
        sorted.sort_unstable();
        if sorted.windows(2).any(|w|w[0].0==w[1].0){return None}
        Some(Self{terms:members,sorted,rows,plain,limit:MAX_PLAIN})
    }
    #[inline] fn pos(&self,t:usize)->Option<usize>{
        self.sorted.binary_search_by_key(&t,|p|p.0).ok().map(|i|self.sorted[i].1)
    }
    #[inline] fn slot(a:usize,b:usize)->Option<(usize,usize)>{
        (a!=b).then(||(a.min(b),a.abs_diff(b)-1))
    }
    fn record(&self,i:usize,d:usize)->SeparationRecord{
        let (x,y)=(self.terms[i],self.terms[i+1+d]);
        SeparationRecord{left:x.min(y),right:x.max(y),reason:ReasonId::new(2*(u64::from(self.rows[i].base)+d as u64)+2)}
    }
    fn at(&self,a:usize,b:usize)->PartitionResult<Option<(EdgeId,SeparationRecord)>>{
        let (Some(x),Some(y))=(self.pos(a),self.pos(b)) else{return Ok(None)};
        let Some((i,d))=Self::slot(x,y) else{return Ok(None)};
        let r=&self.rows[i];
        if d>=r.live{return Ok(None)}
        let id=r.first.checked_add(d as u64).filter(|_|r.first!=0).ok_or_else(||invalid("invalid virtual edge interval"))?;
        Ok(Some((id,self.record(i,d))))
    }
}

#[derive(Default)]
pub(super) struct Plan { row:Option<usize>, extra:usize, exceeds:bool }
impl Plan {
    #[inline] pub(super) fn capacity_barrier(&self,p:&Partition,id:EdgeId,r:SeparationRecord)->bool{
        // Preview the existing codec only at the boundary; commit remains authoritative.
        self.exceeds && !(self.row.is_some() && p.group_rows.storage().is_some_and(|c|
            c.accepts(id,r,p.row_singleton(r.left) && p.row_singleton(r.right))))
    }
}
impl Slot {
    #[inline] fn group(&self)->Option<&Group>{self.0.as_ref()?.first()?.group.as_ref()}
    #[inline] pub(super) fn active(&self)->bool{self.group().is_some()}
    #[inline] pub(super) fn stamp(&self)->u8{
        self.0.as_ref().map_or(0,|a|if a[0].group.is_some(){1}else{2})
    }
    #[inline] pub(super) fn plan(&self,a:usize,b:usize,id:EdgeId,rec:SeparationRecord,fresh:bool)->Plan{
        let Some(g)=self.group() else{return Plan::default()};
        let (x,y)=(g.pos(a),g.pos(b));
        let extra=usize::from(x.is_some())+usize::from(y.is_some());
        let row=x.zip(y).and_then(|(x,y)|Group::slot(x,y)).and_then(|(i,d)|{
            let r=&g.rows[i];
            (fresh && r.live==d && (d==0 || r.first.checked_add(d as u64)==Some(id)) &&
                g.record(i,d)==rec).then_some(i)
        });
        Plan{row,extra,exceeds:g.plain+extra>g.limit}
    }
    #[inline] pub(super) fn commit(&mut self,plan:Plan,compact:bool,id:EdgeId)->bool{
        let Some(o)=self.0.as_mut().map(|v|&mut v[0]) else{return false};
        let Some(g)=o.group.as_mut() else{return false};  // including a mid-call barrier
        if let Some(i)=plan.row.filter(|_|compact){
            let row=&mut g.rows[i];
            if row.live==0{row.first=id}
            row.live+=1; o.stats.skipped_pairs+=1; o.stats.live_pairs+=1;
            o.stats.peak_pairs=o.stats.peak_pairs.max(o.stats.live_pairs);
            true
        }else{
            g.plain+=plan.extra;
            debug_assert!(g.plain<=g.limit);
            false
        }
    }
}

pub(super) struct Ids<'a>{ physical:Option<btree_set::Iter<'a,EdgeId>>, virtual_id:Option<EdgeId> }
impl Ids<'_>{pub(super) fn single_virtual_id(&self)->Option<EdgeId>{self.virtual_id}}
impl Iterator for Ids<'_>{
    type Item=EdgeId;
    fn next(&mut self)->Option<EdgeId>{
        if let Some(v)=self.virtual_id{
            if self.physical.as_ref().and_then(|p|p.clone().next()).is_none_or(|&p|v<p){
                return self.virtual_id.take()
            }
        }
        self.physical.as_mut()?.next().copied()
    }
    fn size_hint(&self)->(usize,Option<usize>){let len=self.len();(len,Some(len))}
}
impl ExactSizeIterator for Ids<'_>{
    fn len(&self)->usize{self.physical.as_ref().map_or(0,|p|p.len())+usize::from(self.virtual_id.is_some())}
}
struct VirtualNeighbors<'a>{
    group:&'a Group, pos:usize, candidates:std::slice::Iter<'a,(usize,usize)>,
}
impl Iterator for VirtualNeighbors<'_>{
    type Item=usize;
    fn next(&mut self)->Option<usize>{
        self.candidates.find_map(|&(root,other)|Group::slot(self.pos,other).and_then(|(i,d)|
            (d<self.group.rows[i].live).then_some(root)))
    }
}
pub(super) struct Neighbors<'a>{
    physical:Peekable<btree_map::Keys<'a,usize,BTreeSet<EdgeId>>>,
    virtuals:Option<Peekable<VirtualNeighbors<'a>>>,
}
impl Iterator for Neighbors<'_>{
    type Item=usize;
    fn next(&mut self)->Option<usize>{
        let Some(v)=&mut self.virtuals else{return self.physical.next().copied()};
        let Some(&b)=v.peek() else{return self.physical.next().copied()};
        match self.physical.peek().copied().copied(){
            Some(a) if a<b=>self.physical.next().copied(),
            Some(a) if a==b=>{self.physical.next();v.next()}
            _=>v.next(),
        }
    }
}

impl Partition {
    pub(super) fn register_rows_and_adjacency(&mut self,terms:&[TermId],bases:&[u32],explicit:Option<bool>,force:Option<bool>)->bool{
        if !terms.iter().all(|&t|self.row_singleton(t)){return false}
        let first=self.group_rows.get().is_none();
        let n=self.term_count();
        let admitted=match explicit {
            None=>self.group_rows.register(terms,bases,n),
            Some(e)=>self.group_rows.register_mode(terms,bases,n,Some(e)),
        };
        if admitted && first && self.group_rows.storage().is_some() && force.unwrap_or_else(||
            std::env::var_os("VPR_VIRTUAL_ADJACENCY").is_some_and(|s|s=="on")){
            if let Some(g)=Group::new(self,terms,bases){
                let mut v=Vec::new();
                if v.try_reserve_exact(1).is_ok(){
                    v.push(Owner{group:Some(g),stats:VirtualAdjacencyStats::default()});
                    self.virtual_rows.0=v.into_boxed_slice().try_into().ok();
                }
            }
        }
        admitted
    }
    #[cfg(test)]
    pub(crate) fn register_group_rows_for_virtual_test(&mut self,terms:&[TermId],bases:&[u32],explicit:bool,virtual_on:bool)->bool{
        self.register_rows_and_adjacency(terms,bases,Some(explicit),Some(virtual_on))
    }
    #[cfg(test)]
    pub(crate) fn physical_adjacency_incidences(&self)->usize{
        self.disequalities.iter().flat_map(|m|m.values()).map(BTreeSet::len).sum()
    }
    #[cfg(test)]
    pub(crate) fn set_virtual_plain_limit_for_test(&mut self,n:usize)->bool{
        let Some(g)=self.virtual_rows.0.as_mut().and_then(|o|o[0].group.as_mut()) else{return false};
        if n<g.plain || n>g.limit{return false}
        g.limit=n;true
    }
    #[inline] pub(crate) fn virtual_adjacency_stats(&self)->super::VirtualAdjacencyStats{
        self.virtual_rows.0.as_ref().map_or_else(VirtualAdjacencyStats::default,|o|o[0].stats)
    }
    #[inline] pub(super) fn has_virtual_adjacency(&self)->bool{
        self.virtual_rows.0.as_ref().is_some_and(|o|o[0].stats.live_pairs!=0)
    }
    #[inline] pub(super) fn virtual_member(&self,root:usize)->bool{
        self.virtual_rows.group().is_some_and(|g|g.pos(root).is_some())
    }

    pub(super) fn logical_ids(&self,a:usize,b:usize)->PartitionResult<Ids<'_>>{
        self.logical_ids_counted::<false>(a,b,&mut 0,&mut None)
    }
    pub(super) fn logical_ids_counted<'a,const COUNT:bool>(&'a self,a:usize,b:usize,first:&mut u64,
        confirmed:&mut Option<btree_set::Iter<'a,EdgeId>>)->PartitionResult<Ids<'a>> {
        let physical=self.physical_ids_between(a,b)?;
        if let Some(ids)=physical.filter(|_|self.has_virtual_adjacency()){
            for &id in ids {
                self.checked_edge_record(a,b,id)?;
                if COUNT{*first+=1;}
            }
            // This exact sorted set was just validated, ID by ID, for (a,b).
            // Borrow it only after success; the enclosing walk cannot mutate it.
            if COUNT{*confirmed=Some(ids.iter());}
        }
        let virtual_id=if let Some(g)=self.virtual_rows.group(){
            if let Some((id,rec))=g.at(a,b)?{
                if physical.is_some_and(|s|s.contains(&id)) || self.size.get(a)!=Some(&1) || self.size.get(b)!=Some(&1) ||
                    self.group_rows.storage().and_then(|c|c.get(id))!=Some(rec){
                    return Err(invalid("virtual edge differs from its unique compact witness"))
                }
                Some(id)
            }else{None}
        }else{None};
        Ok(Ids{physical:physical.map(BTreeSet::iter),virtual_id})
    }
    pub(super) fn logical_neighbors(&self,root:usize)->PartitionResult<Neighbors<'_>>{
        if self.parent.get(root)!=Some(&root){return Err(invalid("logical adjacency requires a current root"))}
        let virtuals=self.virtual_rows.group().and_then(|g|
            g.pos(root).map(|pos|VirtualNeighbors{group:g,pos,candidates:g.sorted.iter()}.peekable()));
        let raw=self.disequalities.get(root).ok_or_else(||invalid("logical adjacency root has no map"))?;
        Ok(Neighbors{physical:raw.keys().peekable(),virtuals})
    }

    pub(super) fn validate_virtual_descriptor(&self)->PartitionResult<()>{
        let Some(g)=self.virtual_rows.group() else{return Ok(())};
        let codec=self.group_rows.storage().ok_or_else(||invalid("virtual adjacency has no compact codec"))?;
        let mut live=0usize;
        for (i,&t) in g.terms.iter().enumerate(){
            if !self.row_singleton(t) || g.pos(t.index())!=Some(i){return Err(invalid("virtual member root or position changed"))}
            let Some(r)=g.rows.get(i) else{continue};
            if r.live>g.terms.len()-i-1 || (r.first==0)!=(r.live==0){return Err(invalid("invalid virtual row prefix"))}
            live+=r.live;
            for d in 0..r.live{
                let id=r.first.checked_add(d as u64).ok_or_else(||invalid("virtual edge id overflow"))?;
                let wanted=g.record(i,d);
                let idx=self.trail.binary_search_by_key(&id,|e|e.state_id).map_err(|_|invalid("virtual edge has no trail entry"))?;
                let j=g.terms[i+1+d].index();
                if codec.get(id)!=Some(wanted) || self.physical_ids_between(t.index(),j)?.is_some_and(|s|s.contains(&id)) ||
                    !matches!(self.trail[idx].undo,Undo::Separation{left_root,right_root,edge_id,record}
                        if edge_id==id && record==wanted && left_root==wanted.left.index() && right_root==wanted.right.index()){
                    return Err(invalid("virtual edge differs from original separation"))
                }
            }
        }
        if live!=self.virtual_adjacency_stats().live_pairs{return Err(invalid("virtual prefix count mismatch"))}
        Ok(())
    }

    pub(super) fn materialize_virtual(&mut self,why:Trigger)->PartitionResult<()>{
        let Some(g)=self.virtual_rows.group() else{return Ok(())};
        self.validate_virtual_descriptor()?;
        let mut plain=0usize;
        for &t in &g.terms {
            let a=t.index();
            for (&b,ids) in &self.disequalities[a]{
                if a==b || self.physical_ids_between(a,b)?.is_none(){return Err(invalid("bad ordinary member adjacency"))}
                plain=plain.checked_add(ids.len()).filter(|&n|n<=g.limit).ok_or_else(||invalid("ordinary incidence cap exceeded"))?;
                for id in ids {
                    let rec=self.row_record(id).ok_or_else(||invalid("ordinary adjacency lost its witness"))?;
                    if normalized_index_pair(self.root_of_term(rec.left)?,self.root_of_term(rec.right)?)!=normalized_index_pair(a,b){
                        return Err(invalid("ordinary witness has different roots"))
                    }
                }
            }
        }
        if plain!=g.plain{return Err(invalid("ordinary incidence count mismatch"))}

        // Validate all sources/directions before replacing anything. B-tree
        // allocations have the same process-OOM behavior as the original maps.
        let mut stage=Vec::new();
        stage.try_reserve_exact(g.terms.len()).map_err(|_|PartitionError::AllocationFailed)?;
        stage.extend(g.terms.iter().map(|t|self.disequalities[t.index()].clone()));
        for (i,r) in g.rows.iter().enumerate(){
            for d in 0..r.live{
                let j=i+1+d;let id=r.first+d as u64;
                if !stage[i].entry(g.terms[j].index()).or_default().insert(id) ||
                    !stage[j].entry(g.terms[i].index()).or_default().insert(id){return Err(invalid("virtual edge has two owners"))}
            }
        }
        for (&t,m) in g.terms.iter().zip(&mut stage){std::mem::swap(&mut self.disequalities[t.index()],m)}
        let owner=&mut self.virtual_rows.0.as_mut().unwrap()[0];
        owner.group=None;
        let s=&mut owner.stats;
        s.materializations+=1;s.materialized_pairs+=s.live_pairs;s.live_pairs=0;
        match why{Trigger::Merge=>s.merge_flushes+=1,Trigger::Rollback=>s.rollback_flushes+=1,Trigger::Capacity=>s.capacity_flushes+=1}
        Ok(())
    }
}
