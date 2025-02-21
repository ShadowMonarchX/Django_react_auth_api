import { createSlice } from '@reduxjs/toolkit';

const initialState = {
  email: "",
};

export const userSlice = createSlice({
  name: 'user_info',
  initialState,
  reducers: {
    setUserInfo: (state, action) => {
      state.email = action.payload.email;
      state.name = action.payload.name;  // This will cause an error if `name` is undefined in your payload.
    },
    unsetUserInfo: (state, action) => {
      state.email = "";
      state.name = "";  // Resetting name to empty string for unset action.
    },
  },
});

export const { setUserInfo, unsetUserInfo } = userSlice.actions;

export default userSlice.reducer;  // Correcting from UserSlice to userSlice
