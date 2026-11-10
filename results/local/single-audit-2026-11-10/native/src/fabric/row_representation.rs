// Included in group_rows.rs. The tracker never chooses a different eligibility policy.
fn parse_representation(value:Option<&std::ffi::OsStr>)->Option<bool>{
    match value {
        None=>Some(false),
        Some(s) if s=="compact"=>Some(false),
        Some(s) if s=="explicit"=>Some(true),
        _=>None,
    }
}
impl Slot {
    #[inline]
    pub(super) fn storage(&self) -> Option<&Codec> {
        self.get().filter(|c| !c.explicit)
    }
    pub(super) fn register_mode(&mut self, terms:&[TermId], bases:&[u32], n:usize,
                                force:Option<bool>)->bool {
        self.register_selected(terms,bases,n,force,||parse_representation(
            std::env::var_os("VPR_ROW_REPRESENTATION").as_deref()))
    }
    fn register_selected(&mut self,terms:&[TermId],bases:&[u32],n:usize,force:Option<bool>,
                         select:impl FnOnce()->Option<bool>)->bool {
        if self.closed_empty {return false}
        if let Some(c)=self.get_mut(){
            return force.is_none_or(|e|e==c.explicit) && c.register(terms,bases,n)
        }
        let mut c=Codec::default();
        if !c.register(terms,bases,n){return false}
        let Some(explicit)=force.or_else(select) else {
            self.closed_empty=true;return false
        };
        c.explicit=explicit;
        let Some(b)=c.owner() else{return false};self.codec=Some(b);true
    }
}

#[cfg(test)]
mod representation_parser_tests {
    use super::*;
    use std::ffi::OsStr;
    #[test]
    fn ablation_representation_invalid_selector_refuses_without_publishing_or_rereading() {
        assert_eq!(parse_representation(None),Some(false));
        for (s,expected) in [("compact",Some(false)),("explicit",Some(true)),("",None),
                              ("EXPLICIT",None),("explicit ",None),("unknown",None)] {
            assert_eq!(parse_representation(Some(OsStr::new(s))),expected);
        }
        #[cfg(unix)] {
            use std::os::unix::ffi::OsStrExt;
            assert_eq!(parse_representation(Some(OsStr::from_bytes(&[0xff]))),None);
        }
        let ts=[TermId::new(0),TermId::new(1)];let mut slot=Slot::default();
        assert!(!slot.register_selected(&ts,&[9],4,None,||None));
        assert!(slot.get().is_none());
        assert!(!slot.register_selected(&ts,&[9],4,None,||panic!("refusal must latch")));
        let mut registered=Slot::default();
        assert!(registered.register_selected(&ts,&[9],4,None,||Some(true)));
        assert!(registered.register_selected(&[TermId::new(2),TermId::new(3)],&[7],4,None,
            ||panic!("existing codec must not reread the mode")));
        assert!(registered.get().unwrap().is_explicit());
    }
}
impl Codec {
    #[inline] pub(super) fn is_explicit(&self)->bool{self.explicit}
    pub(super) fn candidate_arity(&self,atom:u32)->Option<usize>{
        if self.sealed{return None}
        let s=self.specs[self.spec(atom)? as usize];
        Some(self.groups[s.group as usize].terms.len())
    }
    pub(super) fn tracked_group_stats(&self)->Vec<(usize,usize)>{
        self.groups.iter().map(|g|(g.terms.len(),g.live)).collect()
    }
}
