import React from "react";
import ReactDOM from "react-dom/client"; 
import App from "./App";
import reportWebVitals from "./ReportWebVitals";
import { Provider } from "react-redux";
import { store } from "./app/Store";
import "./styles/componentscss/index.css";
import { ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";




const rootElement = document.getElementById("root");

const root = ReactDOM.createRoot(rootElement);

root.render(
  <React.StrictMode>
    <Provider store={store}>
    <ToastContainer />
      <App />
    </Provider>
  </React.StrictMode>
);

reportWebVitals();
