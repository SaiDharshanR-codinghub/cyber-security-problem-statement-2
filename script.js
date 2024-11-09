// Smooth scroll for buttons
document.querySelectorAll(".scroll-btn").forEach((button) => {
  button.addEventListener("click", function (e) {
    e.preventDefault();
    const targetSection = document.querySelector(this.getAttribute("href"));
    targetSection.scrollIntoView({
      behavior: "smooth",
    });
  });
});
