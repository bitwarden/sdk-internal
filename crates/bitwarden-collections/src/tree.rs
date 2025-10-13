use std::{collections::HashMap, fmt::Debug};

use uuid::Uuid;

#[allow(missing_docs)]
pub trait TreeItem: Clone + Debug {
    fn id(&self) -> Uuid;
    /*
    This is the name that will be output when getting the tree nodes
     */
    fn short_name(&self) -> &str;
    /*
    This is the path that the item is stored into a tree
     */
    fn path(&self) -> Vec<&str>;
    const DELIMITER: char;
}

#[allow(missing_docs)]
#[derive(Clone, Debug)]
pub struct TreeIndex<T: TreeItem> {
    pub id: usize, // location in the tree
    pub data: T,   // this will be the raw value
    pub path: Vec<String>,
}

impl<T: TreeItem> TreeIndex<T> {
    #[allow(missing_docs)]
    pub fn new(id: usize, data: &T) -> Self {
        TreeIndex {
            id,
            data: data.clone(),
            path: data.path().iter().map(|s| s.to_string()).collect(),
        }
    }
}

#[allow(missing_docs)]
pub struct NodeItem<T: TreeItem> {
    pub item: T,
    pub parent: Option<T>,
    pub children: Vec<T>,
    pub ancestors: HashMap<Uuid, String>,
}

#[allow(missing_docs)]
pub struct TreeNode {
    pub id: usize,
    pub item_id: Uuid,
    pub parent_idx: Option<usize>,
    pub children_idx: Vec<usize>,
    pub path: Vec<String>,
}

impl TreeNode {
    #[allow(missing_docs)]
    pub fn new<T: TreeItem>(
        id: usize,
        parent_idx: Option<usize>,
        children_idx: Vec<usize>,
        index: TreeIndex<T>,
    ) -> Self {
        TreeNode {
            id,
            item_id: index.data.id(),
            parent_idx,
            children_idx,
            path: index.path,
        }
    }
}

#[allow(missing_docs)]
pub struct Tree<T: TreeItem> {
    pub nodes: Vec<TreeNode>,
    pub items: HashMap<Uuid, TreeIndex<T>>,
    path_to_node: HashMap<Vec<String>, usize>,
}

impl<T: TreeItem> Tree<T> {
    /// Takes vector of TreeItem and stores them into a tree structure.
    pub fn from_items(items: Vec<T>) -> Self {
        let mut tree = Tree {
            nodes: Vec::new(),
            items: HashMap::new(),
            path_to_node: HashMap::new(),
        };

        // sort items
        let sorted_items = {
            let mut i = items.clone();
            i.sort_by(|a, b| a.path().cmp(&b.path()));
            i
        };

        // add items
        for (index, item) in sorted_items.iter().enumerate() {
            let tree_index = TreeIndex::new(index, item);
            tree.items.insert(item.id(), tree_index.clone());
            tree.add_item(tree_index);
        }

        tree
    }

    /// This inserts an item into the tree and sets any look-up information that may be needed.
    fn add_item(&mut self, index: TreeIndex<T>) {
        let parent_path = index.path[0..index.path.len() - 1].to_vec();

        let parent_id = self.path_to_node.get(&parent_path).map(|&id| {
            let parent = &mut self.nodes[id];
            parent.children_idx.push(index.id);
            parent.id
        });

        // add new node
        let node = TreeNode::new(index.id, parent_id, vec![], index);
        self.path_to_node.insert(node.path.clone(), node.id);
        self.nodes.push(node);
    }

    /// Returns an optional node item for a given tree item id.
    ///
    /// This contains the item, its children (or an empty vector), and its parent (if it has one)
    pub fn get_item_by_id(&self, tree_item_id: Uuid) -> Option<NodeItem<T>> {
        let item = self.items.get(&tree_item_id)?;

        self.get_relatives(item)
    }

    fn get_relatives(&self, item: &TreeIndex<T>) -> Option<NodeItem<T>> {
        let node = self.nodes.get(item.id)?;

        // Get the parent if it exists
        let parent = node
            .parent_idx
            .and_then(|pid| self.nodes.get(pid))
            .and_then(|p| self.items.get(&p.item_id))
            .map(|p| p.data.clone());

        // Get any children
        let children: Vec<T> = node
            .children_idx
            .iter()
            .filter_map(|&child_id| self.nodes.get(child_id))
            .filter_map(|child| self.items.get(&child.item_id))
            .map(|i| i.data.clone())
            .collect();

        // Get names and ids of ancestors
        let ancestors = std::iter::successors(node.parent_idx, |&parent_id| {
            self.nodes.get(parent_id).and_then(|node| node.parent_idx)
        })
        .filter_map(|parent_id| {
            self.nodes
                .get(parent_id)
                .and_then(|parent_node| self.items.get(&parent_node.item_id))
                .map(|parent_item| {
                    (
                        parent_item.data.id(),
                        parent_item.data.short_name().to_string(),
                    )
                })
        })
        .collect();

        Some(NodeItem {
            item: item.data.clone(),
            parent,
            children,
            ancestors,
        })
    }

    /// Returns the list of root nodes with their children
    pub fn get_root_items(&self) -> Vec<NodeItem<T>> {
        self.nodes
            .iter()
            .filter(|n| n.parent_idx.is_none())
            .filter_map(|n| self.get_item_by_id(n.item_id))
            .collect()
    }

    /// Returns a flat list of all items in the tree with relationships.
    pub fn get_flat_items(&self) -> Vec<NodeItem<T>> {
        self.items
            .values()
            .filter_map(|i| self.get_relatives(i))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    #[derive(Clone, Debug)]
    pub struct TestItem {
        pub id: Uuid,
        pub name: String,
    }

    impl TreeItem for TestItem {
        fn id(&self) -> Uuid {
            self.id
        }

        fn short_name(&self) -> &str {
            self.path().last().unwrap()
        }

        fn path(&self) -> Vec<&str> {
            self.name
                .split(Self::DELIMITER)
                .filter(|s| !s.is_empty())
                .collect::<Vec<&str>>()
        }

        const DELIMITER: char = '/';
    }

    #[test]
    fn given_collection_with_one_parent_and_two_children_when_getting_parent_then_parent_is_returned_with_children_and_no_parent()
     {
        let parent_id = Uuid::new_v4();
        let items = vec![
            TestItem {
                id: Uuid::new_v4(),
                name: "parent/child1".to_string(),
            },
            TestItem {
                id: parent_id,
                name: "parent".to_string(),
            },
            TestItem {
                id: Uuid::new_v4(),
                name: "parent/child2".to_string(),
            },
        ];

        let node = Tree::from_items(items)
            .get_item_by_id(parent_id)
            .expect("Node not found");

        let item = node.item;
        let parent = node.parent;
        let children = node.children;
        let ancestors = node.ancestors;

        assert_eq!(children.len(), 2);
        assert_eq!(item.id(), parent_id);
        assert_eq!(item.short_name(), "parent");
        assert_eq!(item.path(), ["parent"]);
        assert!(parent.is_none());
        assert!(ancestors.is_empty());
    }

    #[test]
    fn given_collection_with_one_parent_and_two_children_when_getting_child1_then_child1_is_returned_with_no_children_and_a_parent()
     {
        let child_1_id = Uuid::new_v4();
        let parent_id = Uuid::new_v4();
        let items = vec![
            TestItem {
                id: child_1_id,
                name: "parent/child1".to_string(),
            },
            TestItem {
                id: parent_id,
                name: "parent".to_string(),
            },
            TestItem {
                id: Uuid::new_v4(),
                name: "parent/child2".to_string(),
            },
        ];

        let node = Tree::from_items(items)
            .get_item_by_id(child_1_id)
            .expect("Node not found");

        let item = node.item;
        let parent = node.parent;
        let children = node.children;
        let ancestors = node.ancestors;

        assert_eq!(children.len(), 0);
        assert_eq!(item.id(), child_1_id);
        assert_eq!(item.short_name(), "child1");
        assert_eq!(item.path(), ["parent", "child1"]);
        assert_eq!(parent.unwrap().id, parent_id);
        assert_eq!(ancestors.len(), 1);
        assert_eq!(ancestors.get(&parent_id).unwrap(), "parent");
    }

    #[test]
    fn given_collection_with_child_who_has_parent_and_grandparent_returns_correct_ancestors() {
        let child_1_id = Uuid::new_v4();
        let parent_id = Uuid::new_v4();
        let grandparent_id = Uuid::new_v4();
        let items = vec![
            TestItem {
                id: child_1_id,
                name: "grandparent/parent/child".to_string(),
            },
            TestItem {
                id: parent_id,
                name: "grandparent/parent".to_string(),
            },
            TestItem {
                id: grandparent_id,
                name: "grandparent".to_string(),
            },
        ];

        let node = Tree::from_items(items)
            .get_item_by_id(child_1_id)
            .expect("Node not found");

        let item = node.item;
        let parent = node.parent;
        let children = node.children;
        let ancestors = node.ancestors;

        assert_eq!(children.len(), 0);
        assert_eq!(item.id(), child_1_id);
        assert_eq!(item.short_name(), "child");
        assert_eq!(item.path(), ["grandparent", "parent", "child"]);
        assert_eq!(parent.unwrap().id, parent_id);
        assert_eq!(ancestors.len(), 2);
        assert_eq!(ancestors.get(&parent_id).unwrap(), "parent");
        assert_eq!(ancestors.get(&grandparent_id).unwrap(), "grandparent");
    }
}
