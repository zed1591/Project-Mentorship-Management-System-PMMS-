document.addEventListener('DOMContentLoaded', () => {
    const projectWorkspace = document.getElementById('project-workspace');
    if (!projectWorkspace) return;

    const projectId = projectWorkspace.dataset.projectId;
    const addTaskForm = document.getElementById('add-task-form');

    if (addTaskForm) {
        addTaskForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const taskName = document.getElementById('task-name').value;
            const taskDescription = document.getElementById('task-description').value;

            const response = await fetch(`/api/project/${projectId}/task`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ task_name: taskName, description: taskDescription })
            });

            const result = await response.json();
            if (response.ok) {
                alert(result.message);
                // Refresh tasks list or append new task
            } else {
                alert('Failed to add task.');
            }
        });
    }

    // Function to handle task status updates
    function handleTaskStatusUpdate(taskId, newStatus) {
        fetch(`/api/project/${projectId}/task/${taskId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: newStatus })
        })
        .then(response => response.json())
        .then(result => {
            if (response.ok) {
                console.log(result.message);
            }
        })
        .catch(error => console.error('Error updating task status:', error));
    }
});
