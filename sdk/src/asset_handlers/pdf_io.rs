// #[cfg(test)]
// mod tests {
//     #![allow(clippy::expect_used)]
//     #![allow(clippy::panic)]
//     #![allow(clippy::unwrap_used)]

//     use std::{
//         fs::OpenOptions,
//         io::{Cursor, Read, Write},
//     };

//     use lopdf::{Document, IncrementalDocument, Object};

//     #[cfg(target_arch = "wasm32")]
//     wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

//     #[cfg(target_arch = "wasm32")]
//     use wasm_bindgen_test::*;

//     #[cfg_attr(not(target_arch = "wasm32"), test)]
//     #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
//     fn lopdf_can_read_pdf_in_wasm() {
//         let bytes = include_bytes!("../../tests/fixtures/guide.pdf");
//         let document = Document::load_mem(bytes).unwrap();
//         let catalog = document.catalog().unwrap();
//         println!("{:?}", catalog);
//         println!("{:?}", catalog.type_name().unwrap());

//         let names = catalog.get(b"Names").unwrap();
//         let names = document.get_object(names.as_reference().unwrap()).unwrap();
//         println!("{:?}", names);

//         let embedded_files = names.as_dict().unwrap().get(b"EmbeddedFiles").unwrap();
//         println!("{:?}", embedded_files);
//         let embedded_files_ref = embedded_files.as_reference().unwrap();
//         println!("{:?}", embedded_files);
//         let embedded_files = document.get_dictionary(embedded_files_ref).unwrap();
//         println!("{:?}", embedded_files);

//         embedded_files.iter().for_each(|(_id, value)| {
//             println!("ITER FIRST{:?}", value);
//             let value = value.as_array().unwrap();
//             let first = value.first().unwrap();
//             println!("{:?}", first);

//             let first = first.as_str();
//             let mut string = String::new();
//             let first = first.unwrap().read_to_string(&mut string);

//             println!("file name? {:?}", first);
//             let second = value.get(1).unwrap();
//             let second = second.as_reference().unwrap();
//             let second = document.get_object(second).unwrap();
//             println!("{:?}", second);

//             let ef = second.as_dict().unwrap().get(b"EF").unwrap();
//             let ef = ef.as_dict().unwrap();
//             println!("EF {:?}", ef);

//             let f = ef.get(b"F").unwrap();
//             println!("F {:?}", f);

//             let f = f.as_reference().unwrap();
//             let stream = document.get_object(f).unwrap().as_stream().unwrap();
//             println!("{:?}", stream.content.len());
//             let stream = stream.decompressed_content().unwrap();
//             println!("{:?}", stream.len());

//             let mut file = OpenOptions::new()
//                 .write(true)
//                 .create(true)
//                 .open("/Users/dylanross/Desktop/image.jpg")
//                 .unwrap();

//             file.write_all(&stream).unwrap();
//         })
//     }

//     #[cfg_attr(not(target_arch = "wasm32"), test)]
//     #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
//     fn lopdf_can_write_pdf_in_wasm() {
//         let mut buff = Cursor::new(Vec::<u8>::new());
//         let mut doc = Document::new();
//         doc.add_object(Object::Integer(5));
//         assert!(matches!(doc.save_to(&mut buff), Ok(_)));
//         assert!(!buff.get_mut().is_empty());
//     }

//     #[cfg_attr(not(target_arch = "wasm32"), test)]
//     #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
//     fn lopdf_can_write_incremental_pdf_in_wasm() {
//         let mut incremental =
//             IncrementalDocument::load_mem(include_bytes!("../../tests/fixtures/guide.pdf"))
//                 .unwrap();

//         incremental.add_object(Object::Integer(10));
//         incremental.add_object(Object::Integer(20));

//         let mut buff = Cursor::new(Vec::<u8>::new());
//         assert!(matches!(incremental.save_to(&mut buff), Ok(_)));
//     }

//     #[cfg_attr(not(target_arch = "wasm32"), test)]
//     #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
//     fn lopdf_can_read_embedded_files() {
//         let _bytes = include_bytes!("../../tests/fixtures/guide.pdf");
//     }
// }
