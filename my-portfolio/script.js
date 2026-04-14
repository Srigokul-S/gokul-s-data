// Initialize Swiper with a creative 3D effect for a magnificent swipe design
var swiper = new Swiper(".mySwiper", {
    effect: "creative",
    creativeEffect: {
      prev: {
        shadow: true,
        translate: ["-120%", 0, -500],
        rotate: [0, 0, -15]
      },
      next: {
        shadow: true,
        translate: ["120%", 0, -500],
        rotate: [0, 0, 15]
      },
    },
    speed: 800,
    grabCursor: true,
    mousewheel: {
        invert: false,
    },
    keyboard: {
        enabled: true,
    },
    pagination: {
        el: ".swiper-pagination",
        clickable: true,
        dynamicBullets: true,
    },
});
