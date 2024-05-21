use object::{Object, ObjectSymbol};

pub fn main() {
    let data = std::fs::read("/usr/bin/python3.10").unwrap();
    let file = object::File::parse(&*data).unwrap();
    for symbol in file.dynamic_symbols() {
        println!("{:016x} {}", symbol.address(), symbol.name().unwrap());
    }
}
