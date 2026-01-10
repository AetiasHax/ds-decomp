use anyhow::{Result, bail};
use ds_rom::rom::Overlay;

pub struct OverlayGroups {
    groups: Vec<OverlayGroup>,
}

pub type OverlayIndex = u16;

pub struct OverlayGroup {
    pub index: u16,
    pub start_address: u32,
    pub end_address: u32,
    pub overlays: Vec<OverlayIndex>,
    pub after: Vec<OverlayIndex>,
}

impl OverlayGroups {
    pub fn analyze(static_end_address: u32, overlays: &[Overlay]) -> Result<OverlayGroups> {
        // Find all overlays immediately after the static modules (main program and autoloads except ITCM/DTCM)
        let (first_group, first_group_end, mut ungrouped_overlays) =
            overlays.iter().fold((vec![], 0, vec![]), |(mut first_group, mut first_group_end, mut rest), overlay| {
                if overlay.base_address() == static_end_address {
                    first_group.push(overlay.id());
                    first_group_end = first_group_end.max(overlay.end_address())
                } else {
                    rest.push(overlay.id());
                }
                (first_group, first_group_end, rest)
            });
        log::debug!(
            "Found {} overlays after static modules, first group end address: {:#010x}",
            first_group.len(),
            first_group_end
        );

        // Create groups of overlays, starting with the first group found earlier, ordered by base address
        let mut groups = vec![OverlayGroup {
            index: 0,
            start_address: static_end_address,
            end_address: first_group_end,
            overlays: first_group,
            after: vec![],
        }];

        let mut new_group = vec![];
        let mut groups_to_connect = vec![0u16]; // list of groups (indices) which may be preceded by ungrouped overlays
        while !ungrouped_overlays.is_empty() {
            let Some(connect_index) = groups_to_connect.pop() else {
                bail!("No more overlay groups to connect to, are there gaps between overlays?");
            };
            let connect_index = connect_index as usize;

            for i in 0..groups[connect_index].overlays.len() {
                let grouped_overlay = &overlays[groups[connect_index].overlays[i] as usize];
                let overlay_end = grouped_overlay.end_address();

                let mut group_end = 0;
                for j in (0..ungrouped_overlays.len()).rev() {
                    let overlay = &overlays[ungrouped_overlays[j] as usize];
                    if overlay.base_address() == grouped_overlay.end_address() {
                        new_group.push(ungrouped_overlays.remove(j));
                        group_end = group_end.max(overlay.end_address());
                    }
                }

                if !new_group.is_empty() {
                    let after = groups[connect_index]
                        .overlays
                        .iter()
                        .cloned()
                        .filter(|&id| overlays[id as usize].end_address() <= overlay_end)
                        .collect();

                    new_group.reverse();

                    let index = groups.len() as u16;
                    groups.push(OverlayGroup {
                        index,
                        start_address: overlay_end,
                        end_address: group_end,
                        overlays: new_group,
                        after,
                    });
                    groups_to_connect.push(index);

                    new_group = vec![];
                }
            }
        }

        Ok(Self { groups })
    }

    pub fn iter(&self) -> impl Iterator<Item = &OverlayGroup> {
        self.groups.iter()
    }
}
