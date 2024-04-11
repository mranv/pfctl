To revert back to the default changes made by the program, you can follow these steps:

1. **Restore the original configuration file**: If you made changes to the configuration file (e.g., `/Library/Ossec/etc/ossec.conf`), you can replace it with a backup copy of the original file. If you didn't create a backup copy, you might need to manually revert the changes you made to the file, removing the added labels and any other modifications.

2. **Reset firewall rules**: If the program modified the firewall rules using `pfctl`, you can reset the rules to their default state. This typically involves flushing the existing rules and enabling the default rules. You can do this by running the appropriate `pfctl` commands to reset the firewall rules. Here's an example of how you can flush the rules:

    ```sh
    sudo pfctl -F all
    ```

    And then enable the default rules:

    ```sh
    sudo pfctl -E
    ```

    Make sure to consult the documentation or any backup of the previous rules you might have to ensure you're restoring the firewall to the correct state.

By following these steps, you should be able to revert the changes made by the program and restore your system to its default configuration. Make sure to review any changes carefully to avoid unintended consequences.
