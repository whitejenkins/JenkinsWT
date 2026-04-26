const tokenInput = document.getElementById('sourceToken');
const continueBtn = document.getElementById('continueBtn');
const inputError = document.getElementById('inputError');

const saved = localStorage.getItem('jwt.source');
if (saved) tokenInput.value = saved;

continueBtn.addEventListener('click', () => {
  const token = tokenInput.value.trim();
  if (!isLikelyJwt(token)) {
    inputError.textContent = 'Please provide a JWT with 3 dot-separated parts.';
    return;
  }

  localStorage.setItem('jwt.source', token);
  window.location.href = 'attacks.html';
});

function isLikelyJwt(token) {
  return token.split('.').length === 3;
}
