def component_source(effect=None, class_effect=None, display_prefix=None):
    display_name = repr('Module Native Component')
    if display_prefix is not None:
        display_name = repr(display_prefix) + " + str(__import__('os').getpid())"
    lines = [
        'from langflow.custom import Component',
        'from langflow.io import Output, MessageTextInput',
        'from langflow.schema import Data',
        '_fired = [False]',
        'class ModuleNativeComponent(Component):',
        '    display_name = ' + display_name,
        '    name = "ModuleNativeComponent"',
        '    inputs = [MessageTextInput(display_name="Input", name="input_value", value="native-input")]',
        '    outputs = [Output(display_name="Output", name="out", method="build_output")]',
    ]
    if class_effect is not None:
        lines.append('    _snapshot = exec(' + repr(class_effect) + ')')
    if effect is not None:
        lines.append('    @(lambda function: (_fired[0] or (_fired.__setitem__(0, True), exec(' + repr(effect) + ')), function)[-1])')
    lines += ['    def build_output(self) -> Data:', '        return Data(data={"output": "native-output"})']
    return '\n'.join(lines)
