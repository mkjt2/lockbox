def _safe_decode_text_data(data: bytes) -> tuple[str, bool]:
    """
    Safely decode request data to UTF-8 text.
    
    Args:
        data: Raw request data bytes
        
    Returns:
        Tuple of (decoded_text, is_text) where:
        - decoded_text: The decoded string if valid UTF-8, empty string otherwise
        - is_text: True if data was valid UTF-8 text, False otherwise
    """
    if not data:
        return "", True  # Empty data is considered text
    
    try:
        return data.decode("utf-8"), True
    except UnicodeDecodeError:
        return "", False
