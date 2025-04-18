import React from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { logout as teacherLogout } from '../actions/teacherActions';
import { logout as studentLogout } from '../actions/studentActions';
import { NavLink } from "react-router-dom";

function Navbar() {

  const dispatch = useDispatch()

  const teacherLogin = useSelector(state => state.teacherLogin)
  const {loading, error, teacherInfo} = teacherLogin

  const studentLogin = useSelector(state => state.studentLogin)
  const {studentInfo} = studentLogin

  const teacherLogoutHandler = () => {
    dispatch(teacherLogout())
  }

  const studentLogoutHandler = () => {
    dispatch(studentLogout())
  }

  return (
    <div>
      <nav className="navbar navbar-expand-lg navbar-light bg-white shadow">
        <div className="container">
          <NavLink className="navbar-brand fs-3 fw-bold" to="/" exact>
          <span className="text-black">P</span>
                <span className="text-primary">A</span>
                <span className="text-black">T</span>
                <span className="text-primary">H</span>
                <span className="text-black">S</span>
                <span className="text-primary">H</span>
                <span className="text-black">A</span>
                <span className="text-primary">L</span>
                <span className="text-black">A</span>
          </NavLink>
          <button className="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarScroll" aria-controls="navbarScroll" aria-expanded="false" aria-label="Toggle navigation">
            <span className="navbar-toggler-icon"></span>
          </button>
          <div className="collapse navbar-collapse" id="navbarScroll">
            <ul className="navbar-nav me-auto my-2 my-lg-0 navbar-nav-scroll">
              <li className="nav-item">
                <NavLink className="nav-link" aria-current="page" to="/" exact>Home</NavLink>
              </li>
              <li className="nav-item">
                <NavLink className="nav-link" to="/about" exact>About</NavLink>
              </li>
              <li className="nav-item">
                <NavLink className="nav-link" to="/courses" exact>Courses</NavLink>
              </li>
              <li className="nav-item">
                <NavLink className="nav-link" to="/tests" exact>Tests</NavLink>
              </li>
              <li className="nav-item">
                <NavLink className="nav-link" to="/contact" exact>Contact</NavLink>
              </li>
            </ul>
            <div className="navbar align-self-center d-flex">
              
              {teacherInfo ? (
                <>
                  <NavLink className="nav-link text-success" to="/teacher_dashboard" exact title="Dashboard">
                    Hi, <strong>{teacherInfo.tchr_name}</strong>
                  </NavLink>
                  <NavLink className="nav-link" to="/notices" exact title="Notices">
                    <i className="bi-bell text-primary" role="img"></i>
                  </NavLink>
                  <NavLink className="nav-link" onClick={teacherLogoutHandler} to="" title="Logout">
                    <i className="bi-box-arrow-right text-danger" role="img"></i>
                  </NavLink>
                </>
              ) : studentInfo ? (
                <>
                  <NavLink className="nav-link text-primary" to="/student_dashboard" exact title="Dashboard">
                    Hi, <strong>{studentInfo.stud_name}</strong>
                  </NavLink>
                  <NavLink className="nav-link" to="/notices" exact title="Notices">
                    <i className="bi-bell text-primary" role="img"></i>
                  </NavLink>
                  <NavLink className="nav-link" onClick={studentLogoutHandler} to="" title="Logout">
                    <i className="bi-box-arrow-right text-danger" role="img"></i>
                  </NavLink>
                </>
              ) : (
                <>
                  <NavLink className="nav-link" to="/notices" exact title="Notices">
                    <i className="bi-bell text-primary" role="img"></i>
                  </NavLink>
                  <NavLink className="nav-link" to="/student_login" exact title="Student">
                    <i className="bi-person-badge text-primary" role="img"></i>
                  </NavLink>
                  <NavLink className="nav-link" to="/teacher_login" exact title="Teacher">
                    <i className="bi-person-circle text-success" role="img"></i>
                  </NavLink>
                </>
              )}
        
            </div>
          </div>
        </div>
      </nav>
    </div>
  )
}

export default Navbar;
