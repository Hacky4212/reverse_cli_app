from reverse_framework.core.addressing import module_address_model


def test_module_address_model_uses_relative_slide() -> None:
    model = module_address_model(
        preferred_base=0x140000000,
        loaded_base=0x141000000,
        image_size=0x2000,
        module_name="demo.sys",
    )

    assert model["display_mode"] == "rva"
    assert model["slide"] == 0x1000000
    assert model["slide_hex"] == "0x1000000"
    assert model["module_name"] == "demo.sys"
