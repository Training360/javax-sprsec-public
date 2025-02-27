window.onload = function() {
    findEmployees();

    document.querySelector("#create-button").onclick = create;
}

function findEmployees() {
    fetch('http://localhost:8080/api/employees')
        .then(response => response.json())
        .then(employees => print(employees));
}

function print(employees) {
    let table = document.querySelector("#employees-table");
    let rows = "";
    for (let employee of employees) {
        rows +=  `<tr><td>${employee.id}</td><td>${employee.name}</td></tr>`;
    }
    table.innerHTML = rows;
}

function create() {
    const nameInput = document.querySelector("#name-input");
    const name = nameInput.value;
    const jsonData = JSON.stringify({"name": name});

    fetch("api/employees", {
        method: "POST",
        body: jsonData,
        headers: {
            "Content-Type": "application/json"
        }
    })
        .then(response => response.json())
        .then(employee => findEmployees())
    ;

    nameInput.value = "";

    return false;
}