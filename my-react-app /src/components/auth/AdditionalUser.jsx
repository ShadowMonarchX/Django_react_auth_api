import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useDispatch } from "react-redux";
import {
  useAdditionalUserMutation,
  useFetchCountriesQuery,
  useFetchStatesQuery,
  useFetchCitiesQuery,
} from "../../services/UserAuthApi";
import { getToken } from "../../services/LocalStorageService";
import { setUserToken } from "../../app/features/authSlice";
import "../../styles/componentscss/AdditionalUser.css";
import { skipToken } from "@reduxjs/toolkit/query";

function AdditionalUser() {
  const navigate = useNavigate();
  const dispatch = useDispatch();
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [phoneNumber, setPhoneNumber] = useState("");
  const [selectedCountry, setSelectedCountry] = useState("");
  const [selectedState, setSelectedState] = useState("");
  const [selectedCity, setSelectedCity] = useState("");
  const [serverError, setServerError] = useState(null);

  const { data: countries = [], error: countryError } =
    useFetchCountriesQuery();
  const { data: states = [], error: stateError } = useFetchStatesQuery(
    selectedCountry || skipToken
  );
  const { data: cities = [], error: cityError } = useFetchCitiesQuery(
    selectedState || skipToken
  );

  const [additionalUser] = useAdditionalUserMutation();

  useEffect(() => {
    const tokenData = getToken();
    if (tokenData?.access_token && tokenData.access_token !== "undefined") {
      dispatch(setUserToken({ access_token: tokenData.access_token }));
    } else {
      console.error("Token failed.");
    }
  }, [dispatch]);

  const handleSubmit = async (e) => {
    e.preventDefault();

    const access_token = localStorage.getItem("access_token");

    if (!access_token) {
      console.error("No access token found.");
      return;
    }

    const actualData = {
      first_name: firstName,
      last_name: lastName,
      phone_number: phoneNumber,
      country_id: selectedCountry,
      state_id: selectedState,
      city_id: selectedCity,
    };

    try {
      console.log(access_token)
      console.log(actualData)
      if (Array.isArray(actualData.phone_number) && actualData.phone_number.length > 0) {
        actualData.phone_number = actualData.phone_number[0];
      } else if(Array.isArray(actualData.phone_number) && actualData.phone_number.length === 0){
        actualData.phone_number = ""; //or you might need to delete this key
      }
    
      const response = await additionalUser({
        access_token,
        actualData,
      }).unwrap();

      console.log("Success:", response);
      navigate("/Dashboard");
    } catch (error) {
      console.error("Error submitting data:", error);
      setServerError(error.data || { general: "An error occurred." });
    }
  };

  return (
    <div className="home">
      <div className="hero-section">
        <div className="auth-container">
          <h1 className="auth-form-title">User Info</h1>
          <form className="auth-form" onSubmit={handleSubmit}>
            {/* Country Selection */}
            <select
              value={selectedCountry}
              onChange={(e) => setSelectedCountry(e.target.value)}
              required
              className="selection-country"
            >
              <option value="">Select Country</option>
              {countries.map((country) => (
                <option key={country.id} value={country.id}>
                  {country.name}
                </option>
              ))}
            </select>

            {/* State Selection */}
            <select
              value={selectedState}
              onChange={(e) => setSelectedState(e.target.value)}
              required
              disabled={!selectedCountry}
              className="selection-state"
            >
              <option value="">Select State</option>
              {states.length > 0 ? (
                states.map((state) => (
                  <option key={state.id} value={state.id}>
                    {state.name}
                  </option>
                ))
              ) : (
                <option disabled>No states available</option>
              )}
            </select>

            {/* City Selection */}
            <select
              value={selectedCity}
              onChange={(e) => setSelectedCity(e.target.value)}
              required
              disabled={!selectedState}
              className="selection-city"
            >
              <option value="">Select City</option>
              {cities.length > 0 ? (
                cities.map((city) => (
                  <option key={city.id} value={city.id}>
                    {city.name}
                  </option>
                ))
              ) : (
                <option disabled>No cities available</option>
              )}
            </select>

            {/* Input Fields */}
            <input
              type="text"
              placeholder="First Name"
              value={firstName}
              onChange={(e) => setFirstName(e.target.value)}
              required
              className="input-first-name"
            />
            <input
              type="text"
              placeholder="Last Name"
              value={lastName}
              onChange={(e) => setLastName(e.target.value)}
              required
              className="input-last-name"
            />
            <input
              type="text"
              placeholder="Phone Number"
              value={phoneNumber}
              onChange={(e) => setPhoneNumber(e.target.value)}
              required
              className="input-phone-number"
            />

            <button type="submit" className="btn-signin">
              Continue
            </button>
          </form>

          {serverError?.general && (
            <div className="error-message">{serverError.general}</div>
          )}
        </div>
      </div>
    </div>
  );
}

export default AdditionalUser;
