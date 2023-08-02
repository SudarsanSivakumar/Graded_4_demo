package com.gtlearning.empmanagement.service;

import java.util.List;

import com.gtlearning.empmanagement.model.Employee;



public interface EmployeeService {

	List<Employee> getAllEmployees();
	
	Employee saveEmployee(Employee employee);
	
	Employee getEmployeeById(long id);
	
	void deleteEmployeeById(long id);
	

	
}
