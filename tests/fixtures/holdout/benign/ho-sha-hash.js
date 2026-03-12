// codesure: SAFE
const expectedHash = "b94f6f125c79e3a5ffaa826f584c10d52ada669e6762051b826b55776d05a8a";
const actualHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
