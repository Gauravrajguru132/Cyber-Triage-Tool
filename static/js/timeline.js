// Timeline Filter & Search Controller
document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('timelineSearch');
    const filterSelect = document.getElementById('severityFilter');
    const timelineItems = document.querySelectorAll('.timeline-item');

    function applyFilters() {
        const query = (searchInput ? searchInput.value : '').toLowerCase();
        const severity = (filterSelect ? filterSelect.value : 'ALL').toUpperCase();

        timelineItems.forEach(item => {
            const itemSeverity = (item.dataset.severity || '').toUpperCase();
            const itemText = item.innerText.toLowerCase();

            const matchesQuery = !query || itemText.includes(query);
            const matchesSeverity = severity === 'ALL' || itemSeverity === severity;

            if (matchesQuery && matchesSeverity) {
                item.style.display = 'block';
            } else {
                item.style.display = 'none';
            }
        });
    }

    if (searchInput) searchInput.addEventListener('input', applyFilters);
    if (filterSelect) filterSelect.addEventListener('change', applyFilters);
});
