use crate::cipher::login::UriMatchType;

pub(crate) trait HasDuplicates<LoginListView> {
    fn find_duplicates(&self, strategy: UriMatchType) -> Vec<LoginListView>;
}