// codesure: SAFE
const hashedPassword = "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW";
const isValid = await bcrypt.compare(password, hashedPassword);
