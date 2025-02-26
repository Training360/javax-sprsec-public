fetch("http://localhost:8081/api/employees")
.then(response => response.json())
.then(employees => {
    const ul = document.querySelector("#employees-ul");
    for (const employee of employees) {
        ul.innerHTML += `<li>${employee.name}</li>`;
    }
});

fetch("http://localhost:8081/actuator/health")
.then(response => response.json())
.then(health => {
    const div = document.querySelector("#status-div");
    div.innerHTML = health.status;
});