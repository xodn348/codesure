// codesure: SAFE
const res = await fetch('https://api.stripe.com/v1/charges');
const charges = await res.json();
