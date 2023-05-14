pub mod wad_helper;

use std::collections::HashMap;
use std::str;

extern crate flame;
// Parameter of a message, such as
// <PlayerGID TYPE="GID"></PlayerGID>
pub struct MessageField {
    pub name: String,
    pub typename: String,
}

impl MessageField {
    fn new(name: String, typename: String) -> Self {
        MessageField { name, typename }
    }
}

// Message, such as
/*
<MSG_REQUESTRADIALFRIENDQUICKCHAT>
      <RECORD>
         <_MsgName TYPE="STR" NOXFER="TRUE">MSG_REQUESTRADIALFRIENDQUICKCHAT</_MsgName>
         <_MsgDescription TYPE="STR" NOXFER="TRUE">Client-initiated radial friend quick chat request</_MsgDescription>
         <_MsgHandler TYPE="STR" NOXFER="TRUE">MSG_RequestRadialFriendQuickChat</_MsgHandler>
      </RECORD>
</MSG_REQUESTRADIALFRIENDQUICKCHAT>
*/
pub struct Message {
    pub name: String,
    desc: String,
    handler: String,
    access_level: String,
    msg_order: i32,
    pub args: Vec<MessageField>,
}

impl Message {
    fn new(
        name: String,
        desc: String,
        handler: String,
        access_level: String,
        msg_order: i32,
        args: Vec<MessageField>,
    ) -> Message {
        Message {
            name,
            desc,
            handler,
            access_level,
            msg_order,
            args,
        }
    }
}

// Message service, such as
/*
<GameMessages>
  <_ProtocolInfo>
    <RECORD>
      <ServiceID TYPE="UBYT">5</ServiceID>
      <ProtocolType TYPE="STR">GAME</ProtocolType>
      <ProtocolVersion TYPE="INT">1</ProtocolVersion>
      <ProtocolDescription TYPE="STR">Game Messages</ProtocolDescription>
    </RECORD>
  </_ProtocolInfo>
</GameMessage>
 */
pub struct Service {
    id: u8,
    pub name: String,
    version: i32,
    description: String,
    pub messages: Vec<Message>,
}

impl Service {
    #[flame]
    pub fn get_message(&self, name: String) -> Option<(&Message, usize)> {
        for (i, msg) in self.messages.iter().enumerate() {
            if msg.name == name {
                return Some((msg, i));
            }
        }
        return None;
    }

    #[flame]
    pub fn message_table(services: &HashMap<u8, Service>) -> HashMap<String, u8> {
        let mut ret: HashMap<String, u8> = Default::default();
        for (service_id, service) in services.iter() {
            let messages = &service.messages;
            for message in messages.iter() {
                ret.insert(String::from(&message.name), *service_id);
            }
        }
        ret
    }

    fn new(
        id: u8,
        name: String,
        version: i32,
        description: String,
        messages: Vec<Message>,
    ) -> Service {
        Service {
            id,
            name,
            version,
            description,
            messages,
        }
    }
}

#[flame]
fn get_messages_xml() -> Vec<(String, Vec<u8>)> {
    let mut file_list = wad_helper::FileList::get_file_list(
        r#"/home/binarybandit/.wine/drive_c/ProgramData/KingsIsle Entertainment/Wizard101/Data/GameData/Root.wad"#,
    );
    file_list.get_files_with_ext("Messages.xml")
}

fn get_value_from_name(node: roxmltree::Node, name: String) -> String {
    for msg_value in node.children() {
        if msg_value.tag_name().name() == name {
            match msg_value.text() {
                Some(t) => return t.to_string(),
                None => return String::from("None"),
            }
        }
    }
    String::from("-1")
}

#[flame]
pub fn get_services() -> HashMap<u8, Service> {
    let mut ret: HashMap<u8, Service> = HashMap::new();
    let messages = get_messages_xml();
    for val in messages.iter() {
        let xml_data_str = str::from_utf8(&val.1).unwrap();
        let doc = roxmltree::Document::parse(xml_data_str).unwrap();

        let prot_info_node = doc
            .root()
            .first_child()
            .unwrap()
            .first_element_child()
            .unwrap()
            .first_element_child()
            .unwrap();
        let svc_id = get_value_from_name(prot_info_node, String::from("ServiceID"))
            .parse::<u8>()
            .unwrap();
        let svc_type = get_value_from_name(prot_info_node, String::from("ProtocolType"));
        let svc_ver = get_value_from_name(prot_info_node, String::from("ProtocolVersion"));
        let svc_desc = get_value_from_name(prot_info_node, String::from("ProtocolDescription"));

        let mut msgs = Vec::new();

        for node in doc
            .root()
            .first_child()
            .unwrap()
            .first_element_child()
            .unwrap()
            .next_sibling_element()
            .unwrap()
            .next_siblings()
        {
            let inode = match node.first_element_child() {
                Some(n) => n,
                None => continue,
            };

            let msg_desc = get_value_from_name(inode, String::from("_MsgDescription"));
            let msg_handler = get_value_from_name(inode, String::from("_MsgHandler"));
            let msg_acc_lvl = get_value_from_name(inode, String::from("_MsgAccessLvl"));
            let msg_order = get_value_from_name(inode, String::from("_MsgOrder"));

            let mut args = Vec::new();

            for arg in inode
                .first_element_child()
                .unwrap()
                .next_sibling_element()
                .unwrap()
                .next_siblings()
            {
                //println!("test {}", arg.tag_name().name());
                if arg.tag_name().name().find("_Msg") == None && arg.tag_name().name().len() != 0 {
                    args.push(MessageField::new(
                        arg.tag_name().name().to_string(),
                        match arg.attribute("TYPE") {
                            Some(t) => t.to_string(),
                            None => String::from("Object has no typename...?"),
                        },
                    ))
                }
            }
            let msg = Message::new(
                node.tag_name().name().to_string(),
                msg_desc,
                msg_handler,
                msg_acc_lvl,
                msg_order.parse::<i32>().unwrap(),
                args,
            );
            msgs.push(msg);
        }

        if msgs.get(0).unwrap().msg_order > 0 {
            msgs.sort_by_key(|k| k.msg_order);
        } else {
            msgs.sort_by_key(|k| k.name.clone());
        }

        match ret.get_mut(&svc_id) {
            Some(svc) => {
                println!("Service {} already exists! Appending messages... (this probably shouldn't happen!)", svc_id);
                svc.messages.append(&mut msgs);
            }
            None => {
                let svc = Service::new(
                    svc_id,
                    svc_type,
                    svc_ver.parse::<i32>().unwrap(),
                    svc_desc,
                    msgs,
                );
                //println!("{:#?}", svc);
                ret.insert(svc_id, svc);
            }
        }
    }
    ret
}
