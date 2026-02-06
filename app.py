import streamlit as st
from otp_core import get_latest_otp_for_alias, UDEMY_ALIASES

st.set_page_config(page_title="Udemy OTP Service", layout="centered")

st.title("🔐 Udemy OTP Request Portal")

st.write("Select the Udemy account and click **Get OTP**.")

alias = st.selectbox(
    "Choose Udemy Email",
    sorted(UDEMY_ALIASES)
)

if st.button("Get OTP"):
    with st.spinner("Fetching OTP securely..."):
        success, result = get_latest_otp_for_alias(alias)

    if success:
        st.success("✅ OTP Retrieved Successfully")
        st.code(result["otp"], language="text")
        st.write(f"**Account:** {result['alias']}")
        st.write(f"**Age:** {result['age']} minutes")
    else:
        st.error(f"❌ {result}")