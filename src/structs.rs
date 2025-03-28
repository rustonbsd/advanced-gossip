
use anyhow::bail;
use ed25519_dalek::VerifyingKey;
use ed25519_dalek::{
    ed25519::signature::SignerMut, Signature, SigningKey, SIGNATURE_LENGTH,
};
use ed25519_dalek_hpke::{Ed25519EciesDecryption, Ed25519EciesEncryption};
use serde::{Deserialize, Serialize};

use crate::utils::time_now;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTopic {
    read_policy: ReadPolicy,
    write_policy: WritePolicy,
    owner: VerifyingKey,
    name: String,
}

impl PolicyTopic {
    pub fn write_policy(&self) -> &WritePolicy {
        &self.write_policy
    }

    pub fn read_policy(&self) -> &ReadPolicy {
        &self.read_policy
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReadPolicy {
    All,    
    Custom(Vec<VerifyingKey>),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WritePolicy {
    All,
    Owner(VerifyingKey),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    author: VerifyingKey,
    data: Option<Vec<u8>>,
    raw_data: Vec<u8>,
    signature: Signature,
    timestamp: u64,
    read_policy: ReadPolicy,
}

impl Message {
    pub fn from_bytes(raw_data: Vec<u8>,secret_key: Option<&SigningKey>) -> anyhow::Result<Self> {
        let signature = Signature::from_bytes(&raw_data[0..SIGNATURE_LENGTH].try_into()?);
        let timestamp = u64::from_le_bytes(raw_data[64..72].try_into()?);
        let author = VerifyingKey::from_bytes(raw_data[72..104].try_into()?)?;
        
        let policy_buf_len = u64::from_le_bytes(raw_data[104..112].try_into()?);
        let read_policy = serde_json::from_slice::<ReadPolicy>(&raw_data[112..(112+policy_buf_len as usize)])?;

        let raw_data = raw_data[(112+policy_buf_len as usize)..].to_vec();
        let data = match read_policy.clone() {
            ReadPolicy::All => Some(raw_data.clone()),
            ReadPolicy::Custom(node_ids) => match secret_key {
                Some(secret_key) => {
                    let my_signing_key = SigningKey::from_bytes(secret_key.as_bytes());
                    let my_public_key = my_signing_key.verifying_key();

                    let (data_enc_len_buf, raw_data) = raw_data.split_at(8);
                    let data_enc_len = u64::from_le_bytes(data_enc_len_buf.try_into().unwrap()) as usize;

                    let (data_enc, keys_enc) = raw_data.split_at(data_enc_len);

                    let my_index = if author.eq(&my_public_key) { 
                        Some(0)
                    } else if node_ids.contains(&my_public_key) {
                        match node_ids.iter().position(|&n| n.eq(&my_public_key)){
                            Some(index) => Some(index+1),
                            None => None,
                        }
                    } else {None};
                    println!("my_index: {:?}", my_index);

                    if let Some(index) = my_index  {
                        if index < node_ids.len()+1 {
                            let mut offset = 0u64;
                            for _ in 0..index {
                                let len_buf = keys_enc[offset as usize..(offset as usize+8)].to_vec();
                                offset += u64::from_le_bytes(len_buf.try_into().unwrap()) + 8;
                            }

                            let my_enc_key_len = u64::from_le_bytes(keys_enc[offset as usize..(offset as usize+8)].try_into().unwrap()) as usize;
                            let my_enc_key = keys_enc[(offset as usize+8)..(offset as usize+8+my_enc_key_len)].to_vec();
                            let s_key_bytes = my_signing_key.decrypt(my_enc_key.as_slice())?;
                            let mut s_key_buf = [0u8; 32];
                            s_key_buf.copy_from_slice(s_key_bytes.as_slice());
                            let s_key = SigningKey::from_bytes(&s_key_buf);
                            match s_key.decrypt(&data_enc) {
                                Ok(data) => Some(data),
                                Err(_) => None,
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                },
                None => None,
            }
        };

        let message = Message {
            author: author,
            data: data,
            raw_data: raw_data,
            signature: signature,
            timestamp: timestamp,
            read_policy: read_policy,
        };

        if message.verify() {
            Ok(message)
        } else {
            bail!("message signature invalid")
        }
    }

    fn verify(&self) -> bool {
        let verifying_key = self.author;
        let verify_buf = Message::create_sign_buf(self.timestamp, &self.author, &self.read_policy, &self.raw_data);

        match verifying_key.verify_strict(&verify_buf, &self.signature) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let node_id = self.author;

        let policy_buf = serde_json::to_vec(&self.read_policy).unwrap();
        let policy_buf_len = policy_buf.len() as u64;

        let mut buf = vec![];
        buf.extend_from_slice(&self.signature.to_bytes());
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(node_id.as_bytes());
        buf.extend_from_slice(&policy_buf_len.to_le_bytes());
        buf.extend(&policy_buf);
        buf.extend_from_slice(&self.raw_data);

        buf
    }

    fn create_sign_buf(timestamp: u64, author: &VerifyingKey,read_policy: &ReadPolicy,raw_data: &Vec<u8>) -> Vec<u8> {
        let mut sign_buf = vec![];
        sign_buf.extend_from_slice(&timestamp.to_le_bytes());
        sign_buf.extend_from_slice(author.as_bytes());

        let policy_buf = serde_json::to_vec(read_policy).unwrap();
        let policy_buf_len = policy_buf.len() as u64;
        sign_buf.extend_from_slice(&policy_buf_len.to_le_bytes());
        sign_buf.extend(&policy_buf);

        sign_buf.extend_from_slice(&raw_data);
        sign_buf
    }

    pub fn new(data: &Vec<u8>, secret_key: &SigningKey, read_policy: &ReadPolicy) -> Self {
        let mut my_signing_key = SigningKey::from_bytes(secret_key.as_bytes());
        let my_public_key = my_signing_key.verifying_key();
        let timestamp = time_now();

        // Encryption based read policy enforcement
        let data_final = match read_policy {
            ReadPolicy::All => data.clone(),
            ReadPolicy::Custom(node_ids) => {
                let mut buf = vec![];
                let mut csprng = rand_core::OsRng;
                let s_key = SigningKey::generate(&mut csprng);
                let p_key = s_key.verifying_key();
                let data_enc = p_key.encrypt(data.as_slice()).unwrap();
                let data_enc_len_bytes = (data_enc.len() as u64).to_le_bytes();
                buf.extend_from_slice(&data_enc_len_bytes);
                buf.extend(data_enc);

                // add owner key
                let s_key_bytes = s_key.as_bytes();
                let s_key_enc_owner = my_public_key.encrypt(s_key_bytes).unwrap();
                let s_key_enc_owner_len = s_key_enc_owner.len() as u64;
                buf.extend_from_slice(&s_key_enc_owner_len.to_le_bytes());
                buf.extend(s_key_enc_owner);


                // add allowed node keys
                for allowed_node_id in node_ids {
                    let s_key_enc_node =
                        allowed_node_id.encrypt(allowed_node_id.as_bytes()).unwrap();
                    let s_key_enc_node_len = s_key_enc_node.len() as u64;
                    buf.extend_from_slice(&s_key_enc_node_len.to_le_bytes());
                    buf.extend(s_key_enc_node);
                }
                buf
            }
        };

        let sign_buf = Message::create_sign_buf(timestamp, &my_public_key, read_policy, &data_final);
        let signature = my_signing_key.sign(&sign_buf.as_slice());

        Self {
            author: my_public_key,
            data: Some(data.clone()),
            signature: signature,
            timestamp: timestamp,
            read_policy: read_policy.clone(),
            raw_data: data_final,
        }
    }

    pub fn is_legal(&self, write_policy: &WritePolicy) -> bool {
        match write_policy {
            WritePolicy::All => self.verify(),
            WritePolicy::Owner(node_id) => {
                self.verify() && self.author.eq(&VerifyingKey::from_bytes(node_id.as_bytes()).unwrap())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;
    
    #[test]
    fn test_new_message_to_bytes_from_bytes() {
        let ori_data = "this is my test data".as_bytes();
        let mut csprng = OsRng;
        let secret_key = SigningKey::generate(&mut csprng);

        let message = Message::new(&ori_data.to_vec(), &secret_key, &ReadPolicy::Custom(vec![]));
        assert_eq!(message.clone().data.expect("message.data"), ori_data);

        let to_buf = message.clone().to_bytes();
        let message_from = Message::from_bytes(to_buf, Some(&secret_key)).expect("identical message");
        assert_eq!(message_from.clone().data.unwrap(), ori_data);
    }

    #[test]
    fn test_read_policy_all() {
        let data = "public data".as_bytes();
        let mut csprng = OsRng;
        let secret_key = SigningKey::generate(&mut csprng);

        let message = Message::new(&data.to_vec(), &secret_key, &ReadPolicy::All);
        let to_buf = message.to_bytes();
        
        // Anyone should be able to read without a key
        let message_from = Message::from_bytes(to_buf, None).expect("should decode without key");
        assert_eq!(message_from.data.unwrap(), data);
    }

    #[test]
    fn test_read_policy_custom() {
        let data = "private data".as_bytes();
        let mut csprng = OsRng;
        let author_key = SigningKey::generate(&mut csprng);
        let reader_key = SigningKey::generate(&mut csprng);
        let unauthorized_key = SigningKey::generate(&mut csprng);

        // Create message readable by author and one other key
        let message = Message::new(
            &data.to_vec(), 
            &author_key, 
            &ReadPolicy::Custom(vec![reader_key.verifying_key()])
        );
        let encoded = message.to_bytes();

        // Author should be able to read
        let decoded_author = Message::from_bytes(encoded.clone(), Some(&author_key))
            .expect("author should decode");
        assert_eq!(decoded_author.data.unwrap(), data);

        // Authorized reader should be able to read
        let decoded_reader = Message::from_bytes(encoded.clone(), Some(&reader_key))
            .expect("reader should decode");
        assert_eq!(decoded_reader.data.unwrap(), data);

        // Unauthorized should not be able to read
        let decoded_unauthorized = Message::from_bytes(encoded.clone(), Some(&unauthorized_key))
            .expect("should decode metadata");
        assert!(decoded_unauthorized.data.is_none());

        // No key should not be able to read
        let decoded_no_key = Message::from_bytes(encoded.clone(), None)
            .expect("should decode metadata");
        assert!(decoded_no_key.data.is_none());
    }

    #[test]
    fn test_write_policy() {
        let mut csprng = OsRng;
        let owner_key = SigningKey::generate(&mut csprng);
        let other_key = SigningKey::generate(&mut csprng);

        let data = "test data".as_bytes();
        let message = Message::new(&data.to_vec(), &owner_key, &ReadPolicy::All);

        // Test WritePolicy::All
        assert!(message.is_legal(&WritePolicy::All));

        // Test WritePolicy::Owner - owner can write
        let owner_policy = WritePolicy::Owner(owner_key.verifying_key());
        assert!(message.is_legal(&owner_policy));

        // Test WritePolicy::Owner - non-owner cannot write
        let other_message = Message::new(&data.to_vec(), &other_key, &ReadPolicy::All);
        assert!(!other_message.is_legal(&owner_policy));
    }

    #[test]
    fn test_invalid_signature() {
        let mut csprng = OsRng;
        let key1 = SigningKey::generate(&mut csprng);
        let key2 = SigningKey::generate(&mut csprng);

        let data = "test data".as_bytes();
        let message = Message::new(&data.to_vec(), &key1, &ReadPolicy::All);
        let mut encoded = message.to_bytes();

        // Corrupt the signature
        encoded[0] ^= 1;

        // Should fail verification
        assert!(Message::from_bytes(encoded, Some(&key2)).is_err());
    }

    #[test]
    fn test_policy_topic() {
        let mut csprng = OsRng;
        let owner_key = SigningKey::generate(&mut csprng);
        
        let topic = PolicyTopic {
            read_policy: ReadPolicy::All,
            write_policy: WritePolicy::Owner(owner_key.verifying_key()),
            owner: owner_key.verifying_key(),
            name: "test topic".to_string(),
        };

        assert_eq!(topic.read_policy(), &ReadPolicy::All);
        assert_eq!(topic.write_policy(), &WritePolicy::Owner(owner_key.verifying_key()));
    }
}
