(function() {
  "use strict"; // Start of use strict

  const sidebar = document.querySelector('.sidebar');
  const sidebarToggles = document.querySelectorAll('#sidebarToggle, #sidebarToggleTop');
  
  if (sidebar) {    
    const collapseElementList = Array.prototype.slice.call(document.querySelectorAll('.sidebar .collapse'))
    const sidebarCollapseList = collapseElementList.map(function (el) { // Renamed parameter to 'el' to prevent variable shadowing
      return new bootstrap.Collapse(el, { toggle: false });
    });

    for (const toggle of sidebarToggles) {

      // Toggle the side navigation
      toggle.addEventListener('click', function(e) {
        document.body.classList.toggle('sidebar-toggled');
        sidebar.classList.toggle('toggled');

        if (sidebar.classList.contains('toggled')) {
          for (const bsCollapse of sidebarCollapseList) {
            bsCollapse.hide();
          }
        }
      });
    }

    // Close any open menu accordions when window is resized below 768px
    window.addEventListener('resize', function() {
      const vw = Math.max(document.documentElement.clientWidth || 0, window.innerWidth || 0);

      if (vw < 768) {
        for (const bsCollapse of sidebarCollapseList) {
          bsCollapse.hide();
        }
      }
    });
  }

  // Prevent the content wrapper from scrolling when the fixed side navigation hovered over
  const fixedNavigation = document.querySelector('body.fixed-nav .sidebar'); // Fixed spelling typo 'fixedNaigation'
  
  if (fixedNavigation) {
    fixedNavigation.addEventListener('wheel', function(e) {
      const vw = Math.max(document.documentElement.clientWidth || 0, window.innerWidth || 0);

      if (vw > 768) {
        const delta = e.deltaY;
        this.scrollTop += (delta > 0 ? 1 : -1) * 30;
        e.preventDefault();
      }
    }, { passive: false }); // Explicitly set passive false to allow e.preventDefault() to block browser scrolling
  }

  const scrollToTop = document.querySelector('.scroll-to-top');
  
  if (scrollToTop) {
    
    // Scroll to top button appear
    window.addEventListener('scroll', function() {
      const scrollDistance = window.pageYOffset;

      //check if user is scrolling up
      if (scrollDistance > 100) {
        scrollToTop.style.display = 'block';
      } else {
        scrollToTop.style.display = 'none';
      }
    });
  }

})(); // End of use strict