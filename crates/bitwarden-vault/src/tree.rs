use std::collections::HashMap;
use std::fmt::Debug;
use uuid::Uuid;

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

#[derive(Clone, Debug)]
pub struct TreeIndex<T: TreeItem> {
    pub id: usize, // location in the tree
    pub data: T, // this will be the raw value
    pub path: Vec<String>
}

impl<T: TreeItem> TreeIndex<T> {
    pub fn new(id: usize, data: &T) -> Self {
        TreeIndex {
            id,
            data: data.clone(),
            path: data.path().iter().map(|s| s.to_string()).collect(),
        }
    }
}

pub struct NodeItem<T: TreeItem> {
    pub item: T,
    pub parent: Option<T>,
    pub children: Vec<T>
}

pub struct TreeNode {
    pub id: usize,
    pub item_id: Uuid,
    pub parent_idx: Option<usize>,
    pub children_idx: Vec<usize>,
    pub path: Vec<String>
}

impl TreeNode {
    pub fn new<T: TreeItem>(id: usize, parent_idx: Option<usize>, children_idx: Vec<usize>, index: TreeIndex<T>) -> Self {
        TreeNode {
            id,
            item_id: index.data.id(),
            parent_idx,
            children_idx,
            path: index.path,
        }
    }
}

pub struct Tree<T: TreeItem> {
    pub nodes: Vec<TreeNode>,
    pub items: Vec<TreeIndex<T>>,
    path_to_node: HashMap<Vec<String>, usize>
}

impl<T: TreeItem> Tree<T> {
    pub fn from_items(items: Vec<T>) -> Self {
        let mut tree = Tree{
            nodes: Vec::new(),
            items: Vec::new(),
            path_to_node: HashMap::new()
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
            tree.items.push(tree_index.clone());

            tree.add_item(tree_index);
        }

        tree
    }

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

    fn get_item_by_id(&self, tree_item_id: Uuid) -> Option<NodeItem<T>> {
        let item = self.items.iter().find(|i| i.data.id() == tree_item_id);

        if let Some(item) = item {
            let node = self.nodes.get(item.id)?;

            // Get the parent if it exists
            let parent = node.parent_idx
                .and_then(|pid| self.nodes.get(pid));

            // Get all children nodes
            let children: Vec<&TreeNode> = node.children_idx.iter()
                .filter_map(|&child_id| self.nodes.get(child_id))
                .collect();

            // Get corresponding items
            let parent_item = parent.and_then(|p| self.items.get(p.id));
            let children_items: Vec<&TreeIndex<T>> = children.iter()
                .filter_map(|child| self.items.get(child.id))
                .collect();

            return Some(NodeItem {
                item: item.data.clone(),
                parent: parent_item.map(|p| p.data.clone()),
                children: children_items.iter().map(|i| i.data.clone()).collect()
            })
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use crate::tree::TreeItem;
    
    #[derive(Clone, Debug)]
    pub struct TestItem {
        pub id: Uuid,
        pub name: String
    }
    
    impl TreeItem for TestItem {
        fn id(&self) -> Uuid {
            self.id
        }

        fn short_name(&self) -> &str { self.path().last().unwrap() }

        fn path(&self) -> Vec<&str> {
            self.name
                .split(Self::DELIMITER)
                .filter(|s| !s.is_empty())
                .collect::<Vec<&str>>()
        }

        const DELIMITER: char = '/';
    }
    
    #[test]
    fn given_collection_with_one_parent_and_two_children_when_getting_parent_then_parent_is_returned_with_children_and_no_parent() {
        let parent_id = Uuid::new_v4();
        let items = vec![
            TestItem {
                id: Uuid::new_v4(),
                name: "parent/child1".to_string()
            },
            TestItem {
                id: parent_id,
                name: "parent".to_string()
            },            
            TestItem {
                id: Uuid::new_v4(),
                name: "parent/child2".to_string()
            },
        ];
        
        let node_option = Tree::from_items(items)
            .get_item_by_id(parent_id);
        
        if let Some(node) = node_option {
            let item = node.item;
            let parent = node.parent;
            let children = node.children;
            
            assert_eq!(children.len(), 2);
            assert_eq!(item.id(), parent_id);
            assert_eq!(item.short_name(), "parent");
            assert_eq!(item.path(), ["parent"]);
            assert!(parent.is_none());
        } else {
            panic!("Node not found");
        }
    }

    #[test]
    fn given_collection_with_one_parent_and_two_children_when_getting_child1_then_child1_is_returned_with_no_children_and_a_parent() {
        let child_1_id = Uuid::new_v4();
        let parent_id = Uuid::new_v4();
        let items = vec![
            TestItem {
                id: child_1_id,
                name: "parent/child1".to_string()
            },
            TestItem {
                id: parent_id,
                name: "parent".to_string()
            },
            TestItem {
                id: Uuid::new_v4(),
                name: "parent/child2".to_string()
            },
        ];

        let node_option = Tree::from_items(items)
            .get_item_by_id(child_1_id);

        if let Some(node) = node_option {
            let item = node.item;
            let parent = node.parent;
            let children = node.children;

            assert_eq!(children.len(), 0);
            assert_eq!(item.id(), child_1_id);
            assert_eq!(item.short_name(), "child1");
            assert_eq!(item.path(), ["parent", "child1"]);
            assert_eq!(parent.unwrap().id, parent_id);
        } else {
            panic!("Node not found");
        }
    }

    #[test]
    fn given_collection_with_two_children_where_there_parent_node_does_not_exist_children_are_returned_correctly() {
        let child_1_id = Uuid::new_v4();
        let grandparent_id = Uuid::new_v4();
        let items = vec![
            TestItem {
                id: child_1_id,
                name: "grandparent/parent/child1".to_string()
            },
            TestItem {
                id: Uuid::new_v4(),
                name: "grandparent/parent/child2".to_string()
            },
            TestItem {
                id: grandparent_id,
                name: "grandparent".to_string()
            },
        ];

        let node_option = Tree::from_items(items)
            .get_item_by_id(child_1_id);

        if let Some(node) = node_option {
            let item = node.item;
            let parent = node.parent;
            let children = node.children;

            assert_eq!(children.len(), 0);
            assert_eq!(item.id(), child_1_id);
            assert_eq!(item.short_name(), "child1");
            assert_eq!(item.path(), ["grandparent", "parent", "child1"]);
            assert!(parent.is_none());
        } else {
            panic!("Node not found");
        }
    }
}