package employees;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class EmployeeModel {

    private Long id;

    @NotBlank
    private String name;

    private String owner;

    public EmployeeModel(String name) {
        this.name = name;
    }
}
