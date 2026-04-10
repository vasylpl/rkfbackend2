fetch('http://localhost:5000/register', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email: 'opravdu@funkcni.cz', password: 'heslo123' })
}).then(res => res.json()).then(data => console.log(data));