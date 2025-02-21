import { createSlice } from '@reduxjs/toolkit';

const initialState = {
  access_token: null,
};

export const authSlice = createSlice({
  name: 'auth_token',
  initialState,
  reducers: {
    setUserToken: (state, action) => {
      state.access_token = action.payload.access_token;
    },
    unSetUserToken: (state, action) => {
      state.access_token = null;  // Or any other logic you'd like when the token is unset.
    },
  },
});

export const { setUserToken, unSetUserToken } = authSlice.actions;

export default authSlice.reducer;  // Change from AuthSlice to authSlice
