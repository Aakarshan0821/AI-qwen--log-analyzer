const state = {
  mouseX: window.innerWidth / 2,
  mouseY: window.innerHeight / 2,
  showPassword: false,
  passwordLength: 0,
  isTyping: false,
  isLookingAtEachOther: false,
  isPurplePeeking: false,
  isPurpleBlinking: false,
  isBlackBlinking: false,
};

const refs = {
  purple: document.getElementById("purpleCharacter"),
  black: document.getElementById("blackCharacter"),
  yellow: document.getElementById("yellowCharacter"),
  orange: document.getElementById("orangeCharacter"),
  purpleEyes: document.getElementById("purpleEyes"),
  blackEyes: document.getElementById("blackEyes"),
  yellowPupils: document.getElementById("yellowPupils"),
  orangePupils: document.getElementById("orangePupils"),
  yellowMouth: document.getElementById("yellowMouth"),
  email: document.getElementById("email"),
  password: document.getElementById("password"),
  togglePasswordBtn: document.getElementById("togglePasswordBtn"),
  loginForm: document.getElementById("loginForm"),
  submitBtn: document.getElementById("submitBtn"),
};

const lookTimerState = { timer: null };
const peekTimerState = { timer: null, hideTimer: null };

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function randomRange(min, max) {
  return Math.random() * (max - min) + min;
}

function calculatePosition(el) {
  if (!el) {
    return { faceX: 0, faceY: 0, bodySkew: 0 };
  }
  const rect = el.getBoundingClientRect();
  const centerX = rect.left + rect.width / 2;
  const centerY = rect.top + rect.height / 3;
  const deltaX = state.mouseX - centerX;
  const deltaY = state.mouseY - centerY;
  return {
    faceX: clamp(deltaX / 20, -15, 15),
    faceY: clamp(deltaY / 30, -10, 10),
    bodySkew: clamp(-deltaX / 120, -6, 6),
  };
}

function calculateEyeOffset(container, maxDistance, forceLookX, forceLookY) {
  if (!container) return { x: 0, y: 0 };
  if (typeof forceLookX === "number" && typeof forceLookY === "number") {
    return { x: forceLookX, y: forceLookY };
  }

  const rect = container.getBoundingClientRect();
  const centerX = rect.left + rect.width / 2;
  const centerY = rect.top + rect.height / 2;
  const deltaX = state.mouseX - centerX;
  const deltaY = state.mouseY - centerY;
  const distance = Math.min(Math.sqrt(deltaX ** 2 + deltaY ** 2), maxDistance);
  const angle = Math.atan2(deltaY, deltaX);
  return { x: Math.cos(angle) * distance, y: Math.sin(angle) * distance };
}

function updateEyeBall(eyeEl, opts) {
  if (!eyeEl) return;
  const pupil = eyeEl.querySelector(".pupil");
  if (!pupil) return;
  if (opts.isBlinking) {
    eyeEl.style.height = "2px";
    pupil.style.transform = "translate(0px, 0px)";
    return;
  }

  eyeEl.style.height = opts.eyeSize + "px";
  const pos = calculateEyeOffset(eyeEl, opts.maxDistance, opts.forceLookX, opts.forceLookY);
  pupil.style.transform = `translate(${pos.x}px, ${pos.y}px)`;
}

function updateRawPupil(pupilEl, maxDistance, forceLookX, forceLookY) {
  if (!pupilEl) return;
  const pos = calculateEyeOffset(pupilEl, maxDistance, forceLookX, forceLookY);
  pupilEl.style.transform = `translate(${pos.x}px, ${pos.y}px)`;
}

function refreshPeekLoop() {
  if (peekTimerState.timer) clearTimeout(peekTimerState.timer);
  if (peekTimerState.hideTimer) clearTimeout(peekTimerState.hideTimer);
  state.isPurplePeeking = false;

  if (!(state.passwordLength > 0 && state.showPassword)) return;

  const schedule = () => {
    peekTimerState.timer = setTimeout(() => {
      state.isPurplePeeking = true;
      peekTimerState.hideTimer = setTimeout(() => {
        state.isPurplePeeking = false;
        schedule();
      }, 800);
    }, randomRange(2000, 5000));
  };
  schedule();
}

function setTyping(flag) {
  state.isTyping = flag;
  if (!flag) {
    state.isLookingAtEachOther = false;
    if (lookTimerState.timer) clearTimeout(lookTimerState.timer);
    return;
  }
  state.isLookingAtEachOther = true;
  if (lookTimerState.timer) clearTimeout(lookTimerState.timer);
  lookTimerState.timer = setTimeout(() => {
    state.isLookingAtEachOther = false;
  }, 800);
}

function startBlinkLoop(key, setter) {
  const run = () => {
    setTimeout(() => {
      setter(true);
      setTimeout(() => {
        setter(false);
        run();
      }, 150);
    }, randomRange(3000, 7000));
  };
  run();
}

function updateCharacters() {
  const purplePos = calculatePosition(refs.purple);
  const blackPos = calculatePosition(refs.black);
  const yellowPos = calculatePosition(refs.yellow);
  const orangePos = calculatePosition(refs.orange);
  const passwordHidden = state.passwordLength > 0 && !state.showPassword;
  const passwordVisible = state.passwordLength > 0 && state.showPassword;

  if (refs.purple) {
    refs.purple.style.height = state.isTyping || passwordHidden ? "440px" : "400px";
    if (passwordVisible) {
      refs.purple.style.transform = "skewX(0deg)";
    } else if (state.isTyping || passwordHidden) {
      refs.purple.style.transform = `skewX(${purplePos.bodySkew - 12}deg) translateX(40px)`;
    } else {
      refs.purple.style.transform = `skewX(${purplePos.bodySkew}deg)`;
    }
  }

  if (refs.black) {
    if (passwordVisible) {
      refs.black.style.transform = "skewX(0deg)";
    } else if (state.isLookingAtEachOther) {
      refs.black.style.transform = `skewX(${blackPos.bodySkew * 1.5 + 10}deg) translateX(20px)`;
    } else if (state.isTyping || passwordHidden) {
      refs.black.style.transform = `skewX(${blackPos.bodySkew * 1.5}deg)`;
    } else {
      refs.black.style.transform = `skewX(${blackPos.bodySkew}deg)`;
    }
  }

  if (refs.orange) {
    refs.orange.style.transform = passwordVisible ? "skewX(0deg)" : `skewX(${orangePos.bodySkew}deg)`;
  }

  if (refs.yellow) {
    refs.yellow.style.transform = passwordVisible ? "skewX(0deg)" : `skewX(${yellowPos.bodySkew}deg)`;
  }

  if (refs.purpleEyes) {
    refs.purpleEyes.style.left = passwordVisible
      ? "20px"
      : state.isLookingAtEachOther
        ? "55px"
        : `${45 + purplePos.faceX}px`;
    refs.purpleEyes.style.top = passwordVisible
      ? "35px"
      : state.isLookingAtEachOther
        ? "65px"
        : `${40 + purplePos.faceY}px`;
  }

  if (refs.blackEyes) {
    refs.blackEyes.style.left = passwordVisible
      ? "10px"
      : state.isLookingAtEachOther
        ? "32px"
        : `${26 + blackPos.faceX}px`;
    refs.blackEyes.style.top = passwordVisible
      ? "28px"
      : state.isLookingAtEachOther
        ? "12px"
        : `${32 + blackPos.faceY}px`;
  }

  if (refs.orangePupils) {
    refs.orangePupils.style.left = passwordVisible ? "50px" : `${82 + orangePos.faceX}px`;
    refs.orangePupils.style.top = passwordVisible ? "85px" : `${90 + orangePos.faceY}px`;
  }

  if (refs.yellowPupils) {
    refs.yellowPupils.style.left = passwordVisible ? "20px" : `${52 + yellowPos.faceX}px`;
    refs.yellowPupils.style.top = passwordVisible ? "35px" : `${40 + yellowPos.faceY}px`;
  }

  if (refs.yellowMouth) {
    refs.yellowMouth.style.left = passwordVisible ? "10px" : `${40 + yellowPos.faceX}px`;
    refs.yellowMouth.style.top = passwordVisible ? "88px" : `${88 + yellowPos.faceY}px`;
  }

  const purpleEyeForceX = passwordVisible ? (state.isPurplePeeking ? 4 : -4) : state.isLookingAtEachOther ? 3 : null;
  const purpleEyeForceY = passwordVisible ? (state.isPurplePeeking ? 5 : -4) : state.isLookingAtEachOther ? 4 : null;
  const blackEyeForceX = passwordVisible ? -4 : state.isLookingAtEachOther ? 0 : null;
  const blackEyeForceY = passwordVisible ? -4 : state.isLookingAtEachOther ? -4 : null;
  const plainForceX = passwordVisible ? -5 : null;
  const plainForceY = passwordVisible ? -4 : null;

  document.querySelectorAll('[data-eyeball^="purple"]').forEach((eyeEl) => {
    updateEyeBall(eyeEl, {
      eyeSize: 18,
      maxDistance: 5,
      isBlinking: state.isPurpleBlinking,
      forceLookX: purpleEyeForceX,
      forceLookY: purpleEyeForceY,
    });
  });

  document.querySelectorAll('[data-eyeball^="black"]').forEach((eyeEl) => {
    updateEyeBall(eyeEl, {
      eyeSize: 16,
      maxDistance: 4,
      isBlinking: state.isBlackBlinking,
      forceLookX: blackEyeForceX,
      forceLookY: blackEyeForceY,
    });
  });

  document.querySelectorAll('[data-pupil^="orange"]').forEach((pupilEl) => {
    updateRawPupil(pupilEl, 5, plainForceX, plainForceY);
  });
  document.querySelectorAll('[data-pupil^="yellow"]').forEach((pupilEl) => {
    updateRawPupil(pupilEl, 5, plainForceX, plainForceY);
  });
}

function animate() {
  updateCharacters();
  requestAnimationFrame(animate);
}

window.addEventListener("mousemove", (event) => {
  state.mouseX = event.clientX;
  state.mouseY = event.clientY;
});

if (refs.email) {
  refs.email.addEventListener("focus", () => setTyping(true));
  refs.email.addEventListener("blur", () => setTyping(false));
}

if (refs.password) {
  refs.password.addEventListener("input", (event) => {
    state.passwordLength = event.target.value.length;
    refreshPeekLoop();
  });
}

if (refs.togglePasswordBtn && refs.password) {
  refs.togglePasswordBtn.addEventListener("click", () => {
    state.showPassword = !state.showPassword;
    refs.password.type = state.showPassword ? "text" : "password";
    refs.togglePasswordBtn.textContent = state.showPassword ? "隐藏" : "显示";
    refreshPeekLoop();
  });
}

if (refs.loginForm && refs.submitBtn) {
  refs.loginForm.addEventListener("submit", () => {
    refs.submitBtn.disabled = true;
    refs.submitBtn.textContent = "登录中...";
  });
}

startBlinkLoop("purple", (value) => {
  state.isPurpleBlinking = value;
});
startBlinkLoop("black", (value) => {
  state.isBlackBlinking = value;
});

animate();
