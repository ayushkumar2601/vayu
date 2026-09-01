document.addEventListener("DOMContentLoaded", () => {
  // Mobile Menu Logic
  const burger = document.querySelector(".burger");
  const overlay = document.querySelector(".mobile-overlay");
  const menu = document.querySelector(".mobile-menu");
  const links = document.querySelectorAll(".mobile-nav a");

  function closeMenu() {
    burger.setAttribute("aria-expanded", "false");
    overlay.classList.add("hidden");
    menu.classList.add("hidden");
    document.body.classList.remove("menu-open");
  }

  function openMenu() {
    burger.setAttribute("aria-expanded", "true");
    overlay.classList.remove("hidden");
    menu.classList.remove("hidden");
    document.body.classList.add("menu-open");
  }

  if(burger) {
    burger.addEventListener("click", () => {
      const isExpanded = burger.getAttribute("aria-expanded") === "true";
      if (isExpanded) {
        closeMenu();
      } else {
        openMenu();
      }
    });
  }

  if(overlay) overlay.addEventListener("click", closeMenu);
  links.forEach(link => link.addEventListener("click", closeMenu));
  
  window.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeMenu();
  });

  window.addEventListener("resize", () => {
    if (window.innerWidth > 720) {
      closeMenu();
    }
  });

  // Count up stats
  const stats = document.querySelectorAll(".stat-value");
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        startCounting(entry.target);
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.25 });

  stats.forEach(stat => observer.observe(stat));

  function startCounting(el) {
    const target = parseFloat(el.getAttribute("data-target"));
    const decimals = parseInt(el.getAttribute("data-decimals"), 10);
    const index = Array.from(stats).indexOf(el);
    
    // Custom stagger timing
    const duration = 1500 + index * 80;
    const delay = 480 + index * 90;
    
    const easeOutCubic = t => 1 - Math.pow(1 - t, 3);
    
    setTimeout(() => {
      let start = performance.now();
      
      function update(currentTime) {
        const elapsed = currentTime - start;
        const progress = Math.min(elapsed / duration, 1);
        
        const current = target * easeOutCubic(progress);
        
        el.textContent = current.toFixed(decimals);
        
        if (progress < 1) {
          requestAnimationFrame(update);
        } else {
          el.textContent = target.toFixed(decimals);
        }
      }
      
      requestAnimationFrame(update);
    }, delay);
  }
});
