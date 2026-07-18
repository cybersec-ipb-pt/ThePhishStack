document.addEventListener('DOMContentLoaded', function() {
	AOS.init();

	const hoverAnimationTriggerList = Array.prototype.slice.call(document.querySelectorAll('[data-bss-hover-animate]'));

	hoverAnimationTriggerList.forEach(function (hoverAnimationEl) {
		hoverAnimationEl.addEventListener('mouseenter', function(e){ e.target.classList.add('animated', e.target.dataset.bssHoverAnimate) });
		hoverAnimationEl.addEventListener('mouseleave', function(e){ e.target.classList.remove('animated', e.target.dataset.bssHoverAnimate) });
	});
}, false);