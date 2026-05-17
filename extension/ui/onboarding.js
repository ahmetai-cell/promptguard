// PromptGuard Onboarding

let _step = 1;
const TOTAL = 3;

function goTo(n) {
  document.getElementById(`step-${_step}`).classList.remove("active");
  document.getElementById(`dot-${_step}`).classList.remove("active");
  _step = n;
  document.getElementById(`step-${_step}`).classList.add("active");
  document.getElementById(`dot-${_step}`).classList.add("active");

  document.getElementById("back-btn").disabled = (_step === 1);
  const nextBtn = document.getElementById("next-btn");
  if (_step === TOTAL) {
    nextBtn.textContent = "Done";
    nextBtn.onclick = () => window.close();
  } else {
    nextBtn.textContent = "Next →";
    nextBtn.onclick = () => goTo(_step + 1);
  }
}

document.getElementById("next-btn").addEventListener("click", () => goTo(_step + 1));
document.getElementById("back-btn").addEventListener("click", () => goTo(_step - 1));

document.getElementById("test-btn").addEventListener("click", () => {
  chrome.tabs.create({ url: "https://ahmetai-cell.github.io/promptguard/test.html" });
});

document.getElementById("settings-btn").addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});
