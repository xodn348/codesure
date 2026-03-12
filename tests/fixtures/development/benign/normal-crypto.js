// codesure: SAFE
const hash = crypto.createHash('sha256').update(data).digest('hex');
const hmac = crypto.createHmac('sha256', secret).update(message).digest('hex');
