document.addEventListener('DOMContentLoaded', function() {
    // Toggle comments
    const toggleCommentButtons = document.querySelectorAll('.toggle-comments');
    toggleCommentButtons.forEach(button => {
        button.addEventListener('click', function() {
            const commentsSection = this.nextElementSibling;
            if (commentsSection.style.display === 'none' || commentsSection.style.display === '') {
                commentsSection.style.display = 'block';
            } else {
                commentsSection.style.display = 'none';
            }
        });
    });

    // Like button animation
    const likeButtons = document.querySelectorAll('.btn-like');
    likeButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            button.classList.add('liked');
            setTimeout(() => {
                button.classList.remove('liked');
            }, 1000);
        });
    });
});
