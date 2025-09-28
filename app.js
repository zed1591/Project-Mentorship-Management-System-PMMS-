// This script contains the logic for the dashboard, including fetching analytics and handling user interactions.
document.addEventListener('DOMContentLoaded', () => {

    // --- Custom Modal Functions (Replaces alert() and window.confirm()) ---
    const modalHtml = `
        <div id="custom-modal-container" class="custom-modal-backdrop" style="display:none;">
            <div class="custom-modal-content">
                <p id="modal-message" class="modal-message"></p>
                <div id="modal-buttons" class="modal-buttons"></div>
            </div>
        </div>
    `;
    document.body.insertAdjacentHTML('beforeend', modalHtml);

    const modalContainer = document.getElementById('custom-modal-container');
    const modalMessage = document.getElementById('modal-message');
    const modalButtons = document.getElementById('modal-buttons');

    function showModal(message, type = 'alert') {
        return new Promise(resolve => {
            modalMessage.textContent = message;
            modalButtons.innerHTML = ''; // Clear previous buttons
            
            const buttonClass = (type === 'confirm') ? 'confirm' : 'alert';
            const buttonText = (type === 'confirm') ? 'Delete' : 'OK';
            
            const confirmButton = document.createElement('button');
            confirmButton.className = `modal-button ${buttonClass}`;
            confirmButton.textContent = buttonText;
            confirmButton.onclick = () => {
                modalContainer.style.display = 'none';
                resolve(true);
            };
            modalButtons.appendChild(confirmButton);
            
            if (type === 'confirm') {
                const cancelButton = document.createElement('button');
                cancelButton.className = 'modal-button cancel';
                cancelButton.textContent = 'Cancel';
                cancelButton.onclick = () => {
                    modalContainer.style.display = 'none';
                    resolve(false);
                };
                modalButtons.appendChild(cancelButton);
            }

            modalContainer.style.display = 'flex';
        });
    }

    const showAlert = (message) => showModal(message, 'alert');
    const showConfirm = (message) => showModal(message, 'confirm');

    // --- Core Logic for Coordinator Dashboard ---

    const fetchAnalyticsSummary = async () => {
        try {
            const response = await fetch('/api/summary_analytics'); 
            if (!response.ok) {
                throw new Error('Failed to fetch analytics data');
            }
            const data = await response.json();
            
            // Safely update text content with null checks
            const mentorCountElement = document.getElementById('mentor-count');
            const menteeCountElement = document.getElementById('mentee-count');
            const adminCountElement = document.getElementById('admin-count');
            const totalProjectsElement = document.getElementById('total-projects');
            
            if (mentorCountElement) mentorCountElement.textContent = data.users_by_role?.Mentor || 0;
            if (menteeCountElement) menteeCountElement.textContent = data.users_by_role?.Mentee || 0;
            if (adminCountElement) adminCountElement.textContent = data.users_by_role?.Administrator || 0;
            if (totalProjectsElement) totalProjectsElement.textContent = data.total_projects || 0;
            
        } catch (error) {
            console.error('Error fetching analytics summary:', error);
            showAlert('Failed to load dashboard analytics. Please try again later.');
        }
    };
    
    const fetchMentorsAndPopulateDropdown = async () => {
        try {
            const response = await fetch('/api/available_mentors');
            if (!response.ok) {
                throw new Error('Failed to fetch mentors');
            }
            const mentors = await response.json();
            const selectElement = document.getElementById('mentorSelect');
            if (selectElement) {
                selectElement.innerHTML = '<option value="">-- Select a Mentor --</option>';
                mentors.forEach(mentor => {
                    const option = document.createElement('option');
                    option.value = mentor._id;
                    option.textContent = mentor.username;
                    selectElement.appendChild(option);
                });
            }
        } catch (error) {
            console.error('Error fetching mentors:', error);
            showAlert('Failed to load mentor list for assignment.');
        }
    };

    // --- Event Listeners and Initial Load ---
    fetchAnalyticsSummary();
    fetchMentorsAndPopulateDropdown();
    
    const assignMentorForm = document.getElementById('assignMentorForm');
    if (assignMentorForm) {
        assignMentorForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const projectId = document.getElementById('assignProjectId').value;
            const mentorId = document.getElementById('mentorSelect').value;
            const messageElement = document.getElementById('assignMentorMessage');
            
            if (!messageElement) {
                console.error('Message element not found');
                return;
            }
            
            if (!mentorId) {
                messageElement.textContent = "Please select a mentor.";
                messageElement.classList.remove('success-message');
                messageElement.classList.add('error-message');
                return;
            }

            try {
                const response = await fetch('/api/mentor_match', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ project_id: projectId, mentor_id: mentorId })
                });

                const result = await response.json();
                
                if (response.ok) {
                    messageElement.textContent = result.message;
                    messageElement.classList.remove('error-message');
                    messageElement.classList.add('success-message');
                    showAlert("Mentor assigned successfully!");
                    // Hide the modal or refresh the page
                    window.location.reload(); 
                } else {
                    messageElement.textContent = result.message;
                    messageElement.classList.remove('success-message');
                    messageElement.classList.add('error-message');
                    showAlert(`Failed to assign mentor: ${result.message}`);
                }
            } catch (error) {
                console.error('Error assigning mentor:', error);
                messageElement.textContent = "An error occurred during assignment.";
                messageElement.classList.remove('success-message');
                messageElement.classList.add('error-message');
            }
        });
    }

    // Modal button actions (from HTML)
    window.closeAssignMentorModal = () => {
        const modal = document.getElementById('assignMentorModal');
        if (modal) {
            modal.style.display = 'none';
        }
    };
    
    // Project table interaction
    const projectTable = document.querySelector('.project-list-table');
    if (projectTable) {
        projectTable.addEventListener('click', (e) => {
            if (e.target.classList.contains('assign-mentor-btn')) {
                const projectId = e.target.dataset.projectId;
                const projectIdElement = document.getElementById('assignProjectId');
                if (projectIdElement) {
                    projectIdElement.value = projectId;
                }
                const modal = document.getElementById('assignMentorModal');
                if (modal) {
                    modal.style.display = 'flex';
                    // Trigger mentor list fetch again to ensure it's up-to-date
                    fetchMentorsAndPopulateDropdown();
                }
            }
        });
    }
    
    // --- User Management Functionality ---

    const deleteButtons = document.querySelectorAll('.delete-user-btn');
    
    deleteButtons.forEach(button => {
        button.addEventListener('click', async (e) => {
            const userIdToDelete = e.target.dataset.userId;
            const usernameToDelete = e.target.dataset.username;

            const confirmDelete = await showConfirm(`Are you sure you want to delete user "${usernameToDelete}"? This action cannot be undone.`);

            if (confirmDelete) {
                try { 
                    const csrfToken = document.querySelector('meta[name="csrf-token"]');
                    if (!csrfToken) {
                        showAlert('CSRF token not found. Please refresh the page.');
                        return;
                    }

                    const response = await fetch(`/api/users/${userIdToDelete}`, {
                        method: 'DELETE',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRFToken': csrfToken.getAttribute('content')
                        }
                    });

                    const result = await response.json();

                    if (response.ok) {
                        showAlert(result.message);
                        window.location.href = "{{ url_for('dashboard') }}";
                    } else {
                        showAlert(`Error: ${result.message || 'Failed to delete user.'}`);
                    }
                } catch (error) {
                    console.error('Error deleting user:', error);
                    showAlert('An error occurred. Please try again.');
                }
            }
        });
    });

    // Handle add-task form submission
    const addTaskForm = document.getElementById('add-task-form');
    if (addTaskForm) {
        addTaskForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const projectId = document.getElementById('project-id');
            const taskName = document.getElementById('task-name');
            const taskDescription = document.getElementById('task-description');

            if (!projectId || !taskName || !taskDescription) {
                showAlert('Form elements not found.');
                return;
            }

            try {
                const response = await fetch(`/api/project/${projectId.value}/task`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        task_name: taskName.value, 
                        description: taskDescription.value 
                    })
                });

                const result = await response.json();
                if (response.ok) {
                    showAlert(result.message);
                    // Clear form
                    taskName.value = '';
                    taskDescription.value = '';
                    // Refresh tasks list or append new task
                } else {
                    showAlert('Failed to add task.');
                }
            } catch (error) {
                console.error('Error adding task:', error);
                showAlert('An error occurred. Please try again.');
            }
        });
    }

    // Function to handle task status updates
    function handleTaskStatusUpdate(projectId, taskId, newStatus) {
        fetch(`/api/project/${projectId}/task/${taskId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: newStatus })
        })
        .then(response => response.json())
        .then(result => {
            if (response.ok) {
                console.log(result.message);
                // Update UI accordingly
            }
        })
        .catch(error => console.error('Error updating task status:', error));
    }

    // Error handling for missing elements
    const dashboard = document.getElementById('dashboard-content');
    if (!dashboard) {
        console.log('Dashboard element not found - script loaded on non-dashboard page');
        return;
    }

});
