/* =========================================
   SIGNUP BUTTON
========================================= */

const signupForm =
document.querySelector(".signup-form");

signupForm.addEventListener(
    "submit",
    function(event){

        event.preventDefault();

        alert("Account Created Successfully");

        window.location.href = "/login";
    }
);