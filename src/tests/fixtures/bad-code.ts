// Test fixture - intentionally insecure code for scanner testing
// This file contains intentional security issues for testing purposes

// Hardcoded AWS key (test fixture)
const awsKey = 'AKIAIOSFODNN7ABCDEF12';

// SQL injection pattern
function getUser(req: { query: { id: string } }) {
  const db = { run: (_q: string) => {} };
  db.run('SELECT * FROM users WHERE id = ' + req.query.id);
}

// XSS via innerHTML
function updateContent(userInput: string) {
  const el = document.getElementById('content')!;
  el.innerHTML = userInput;
}

// eval usage
function runCode(code: string) {
  return eval(code);
}

export { getUser, updateContent, runCode };
