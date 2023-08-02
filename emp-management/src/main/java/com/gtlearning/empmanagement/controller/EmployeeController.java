package com.gtlearning.empmanagement.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.gtlearning.empmanagement.model.Employee;
import com.gtlearning.empmanagement.service.EmployeeService;

@RestController
@RequestMapping("/api/v1/employees")
public class EmployeeController {

	@Autowired
	private EmployeeService employeeService;
	
	@GetMapping
	public List<Employee> getAllEmployees(){
		return this.employeeService.getAllEmployees();
	}
	
	@GetMapping("/{id}")
		public Employee getEmployeeById (@PathVariable("id") long id) {
			return this.employeeService.getEmployeeById(id);
		}
	@PostMapping
	public Employee saveEmployee (@RequestBody Employee employee) {
		return this.employeeService.saveEmployee(employee);
	}
	
	@DeleteMapping("delete/{id}")
	public void deleteEmployeeById(@PathVariable("id") long id) {
		this.employeeService.deleteEmployeeById(id);
	}
	
}
