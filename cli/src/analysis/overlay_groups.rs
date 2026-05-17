use std::collections::{BTreeMap, btree_map};

use anyhow::Result;
use ds_rom::rom::Overlay;

pub struct OverlayGroups {
    groups: Vec<OverlayGroup>,
}

pub type OverlayIndex = u16;

pub struct OverlayGroup {
    pub start_address: u32,
    pub end_address: u32,
    pub overlays: Vec<OverlayIndex>,
    pub location: OverlayGroupLocation,
}

#[derive(Clone)]
pub enum OverlayGroupLocation {
    AfterStatic,              // after ARM9 and custom autoloads
    After(Vec<OverlayIndex>), // after other overlays
    Static,                   // static address
}

struct OverlaySuccessors {
    overlays: Vec<u16>,
    precedes: OverlayGroupLocation,
}

impl OverlayGroups {
    pub fn analyze(static_end_address: u32, overlays: &[Overlay]) -> Result<Self> {
        // Map end addresses to modules
        let mut precedents: BTreeMap<u32, OverlayGroupLocation> = BTreeMap::new();
        precedents.insert(static_end_address, OverlayGroupLocation::AfterStatic);
        for overlay in overlays {
            match precedents.entry(overlay.end_address()) {
                btree_map::Entry::Vacant(entry) => {
                    entry.insert(OverlayGroupLocation::After(vec![overlay.id()]));
                }
                btree_map::Entry::Occupied(mut entry) => {
                    let OverlayGroupLocation::After(overlays) = entry.get_mut() else {
                        unreachable!();
                    };
                    overlays.push(overlay.id());
                }
            };
        }
        let precedents = precedents;

        // Map base addresses to overlays and precedents
        let mut successors_map: BTreeMap<u32, OverlaySuccessors> = BTreeMap::new();
        for overlay in overlays {
            match successors_map.entry(overlay.base_address()) {
                btree_map::Entry::Vacant(entry) => {
                    let precedes = if let Some(precedes) = precedents.get(&overlay.base_address()) {
                        precedes.clone()
                    } else {
                        OverlayGroupLocation::Static
                    };
                    entry.insert(OverlaySuccessors { overlays: vec![overlay.id()], precedes });
                }
                btree_map::Entry::Occupied(mut entry) => {
                    entry.get_mut().overlays.push(overlay.id());
                }
            };
        }
        let successors_map = successors_map;

        // Create overlay groups
        let mut groups = Vec::new();
        let mut group_index_by_overlay = vec![None; overlays.len()];
        for (base_address, successors) in successors_map {
            let end_address = successors
                .overlays
                .iter()
                .map(|&id| overlays[id as usize].end_address())
                .max()
                .unwrap();

            let location = match successors.precedes {
                OverlayGroupLocation::AfterStatic => OverlayGroupLocation::AfterStatic,
                OverlayGroupLocation::Static => OverlayGroupLocation::Static,
                OverlayGroupLocation::After(items) => {
                    let mut group_indices = items
                        .iter()
                        .map(|&id| group_index_by_overlay[id as usize].unwrap())
                        .collect::<Vec<_>>();
                    group_indices.sort_unstable();
                    group_indices.dedup();
                    let preceding_overlays = group_indices
                        .iter()
                        .flat_map(|&group_index| {
                            let group: &OverlayGroup = &groups[group_index];
                            group
                                .overlays
                                .iter()
                                .filter(|&&id| overlays[id as usize].end_address() <= base_address)
                                .copied()
                        })
                        .collect();
                    OverlayGroupLocation::After(preceding_overlays)
                }
            };

            for &overlay in &successors.overlays {
                group_index_by_overlay[overlay as usize] = Some(groups.len());
            }
            groups.push(OverlayGroup {
                start_address: base_address,
                end_address,
                overlays: successors.overlays,
                location,
            });
        }

        Ok(Self { groups })
    }

    pub fn iter(&self) -> impl Iterator<Item = &OverlayGroup> {
        self.groups.iter()
    }

    pub fn last(&self) -> Option<&OverlayGroup> {
        self.groups.last()
    }
}
