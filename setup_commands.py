import discord
import asyncio
import logging
import random
import time
from datetime import datetime
from discord import app_commands
from discord.ext import commands
from difflib import SequenceMatcher
from typing import List, Dict, Optional, Union
import json

from utils.config import get_server_config, update_server_config, save_guild_config, get_default_config
from utils.permissions import is_admin # Removed can_use_command as /setup is admin only
from utils.logging import log_action
from utils.embeds import EmbedBuilder
from utils.team_detection import detect_team_roles, generate_team_name_from_role, find_team_emoji # find_team_emoji might be unused if emojis are directly in config

logger = logging.getLogger("bot.setup")

DEFAULT_ROSTER_CAP = 53 # Consistent default

class SetupCommands(commands.Cog):
    """Cog for handling server setup and configuration commands."""
    def __init__(self, bot):
        self.bot = bot
        self.active_setup_sessions = {} # guild_id -> session_data

    async def team_autocomplete(self, interaction: discord.Interaction, current: str) -> List[app_commands.Choice[str]]:
        config = get_server_config(interaction.guild.id)
        team_data_new = config.get("team_data", {})
        team_roles_legacy = config.get("team_roles", {})
        all_teams = sorted(set(list(team_data_new.keys()) + list(team_roles_legacy.keys())))

        choices = [app_commands.Choice(name=team, value=team) for team in all_teams if current.lower() in team.lower() or not current]
        if current.lower() in "all" or not current:
            choices.insert(0, app_commands.Choice(name="All Teams (Global Default)", value="all_teams_global_cap"))
        return choices[:25]

    def cleanup_sessions(self): # Periodically clean up expired sessions
        current_time = time.time()
        expired_user_ids = [
            user_id for user_id, session in self.active_setup_sessions.items()
            if current_time - session.get("timestamp", 0) > 1800 # 30 min expiry
        ]
        for user_id in expired_user_ids:
            self.active_setup_sessions.pop(user_id, None)
            logger.info(f"Cleaned up expired setup session for user {user_id}")


    @app_commands.command(name="gamealerts", description="Configure game reminder settings and notifications")
    @app_commands.default_permissions(administrator=True)
    async def gamealerts(self, interaction: discord.Interaction):
        if not await is_admin(interaction.user): # Redundant with default_permissions but good practice
            await interaction.response.send_message(embed=EmbedBuilder.error("Permission Denied", "You need admin perms."),ephemeral=True)
            return

        guild_id = interaction.guild.id
        config = get_server_config(guild_id) # Load full config

        # notification_settings is guaranteed by get_server_config based on get_default_config
        notification_settings = config["notification_settings"]

        embed = discord.Embed(title="🔔 Game Alerts Configuration", description="Configure game reminders and notifications.", color=discord.Color.blue())

        settings_text_parts = []
        # Use keys from default_config for consistent display order and completeness
        default_config_template = get_default_config()
        default_notification_config_template = default_config_template.get("notification_settings", {})

        for key, default_val in default_notification_config_template.items():
            current_val = notification_settings.get(key, default_val)
            display_name = key.replace("_", " ").title()
            if key == "reminders_channel_id": # Special handling for channel display
                channel_obj = interaction.guild.get_channel(current_val) if current_val else None
                settings_text_parts.append(f"**{display_name}:** {channel_obj.mention if channel_obj else 'Not set'}")
            elif isinstance(default_val, bool): # Toggleable settings
                 settings_text_parts.append(f"**{display_name}:** {'✅ Enabled' if current_val else '❌ Disabled'}")

        embed.add_field(name="Current Settings", value="\n".join(settings_text_parts) or "No notification settings found.", inline=False)

        view = GameAlertsView(self.bot, guild_id, config) # Pass the main config object
        await interaction.response.send_message(embed=embed, view=view, ephemeral=True)


    @app_commands.command(name="autosetup", description="Automatically configure bot with detected items")
    @app_commands.default_permissions(administrator=True)
    @app_commands.describe(threshold="Similarity threshold for matching (0.0 to 1.0, default 0.7)")
    async def autosetup(self, interaction: discord.Interaction, threshold: float = 0.7):
        if not await is_admin(interaction.user):
            await interaction.response.send_message(embed=EmbedBuilder.error("Permission Denied", "Only admins can use this."),ephemeral=True)
            return
        if not 0.0 <= threshold <= 1.0:
            await interaction.response.send_message(embed=EmbedBuilder.error("Invalid Threshold", "Must be between 0.0 and 1.0."),ephemeral=True)
            return

        await interaction.response.defer(ephemeral=True)

        # Use keys from default_config for role_type_map
        default_permission_settings = get_default_config().get("permission_settings", {})
        role_type_map = {key: key.replace("_roles", "").replace("_", " ").title() for key in default_permission_settings.keys()}

        default_log_channels = get_default_config().get("log_channels", {}).keys()
        default_ann_channels = get_default_config().get("announcement_channels", {}).keys()
        # "reminders_channel_id" is special, handled under notification_settings
        channel_config_keys_for_autosetup = list(default_log_channels) + list(default_ann_channels) + ["reminders_channel_id"]


        detected_team_roles = detect_team_roles(interaction.guild) # Assumes this returns list of discord.Role
        team_matches = [{"name": generate_team_name_from_role(r), "role_id": r.id, "emoji": find_team_emoji(interaction.guild, generate_team_name_from_role(r)) or "🏆"} for r in detected_team_roles]

        role_matches = {}
        for role_config_key, display_name_generic in role_type_map.items():
            # Fuzzy match against generic display name (e.g., "Admin", "Moderator")
            role_matches[role_config_key] = sorted(
                [{"role_id": r.id, "name": r.name, "similarity": SequenceMatcher(None, r.name.lower(), display_name_generic.lower()).ratio()}
                 for r in interaction.guild.roles if r.name != "@everyone" and SequenceMatcher(None, r.name.lower(), display_name_generic.lower()).ratio() >= threshold],
                key=lambda x: x["similarity"], reverse=True
            )

        channel_matches = {}
        for channel_config_key in channel_config_keys_for_autosetup:
            # Use the key itself (e.g., "transactions", "reminders_channel_id") for matching logic
            display_name_generic = channel_config_key.replace("_roles","").replace("_channel_id","").replace("_channel","").replace("_", " ").title()
            channel_matches[channel_config_key] = sorted(
                [{"channel_id": c.id, "name": c.name, "similarity": SequenceMatcher(None, c.name.lower(), display_name_generic.lower()).ratio()}
                 for c in interaction.guild.text_channels if SequenceMatcher(None, c.name.lower(), display_name_generic.lower()).ratio() >= threshold],
                key=lambda x: x["similarity"], reverse=True
            )


        if not team_matches:
            await interaction.followup.send(embed=EmbedBuilder.warning("No Teams Detected", "Could not detect team roles. Use `/addteam` or ensure roles follow a common pattern."),ephemeral=True)
            return # Don't proceed if no teams, as teams are fundamental

        view = AutoSetupConfirmationView(self.bot, interaction.guild.id, team_matches, role_matches, channel_matches, role_type_map, channel_config_keys_for_autosetup, threshold, self)
        embed = discord.Embed(title="⚙️ Auto-Setup Confirmation", description="Review detected items and confirm selections.", color=discord.Color.blue())
        # Team summary
        team_summary_val = "\n".join([f"• {team['emoji']} {team['name']} ({interaction.guild.get_role(team['role_id']).mention if interaction.guild.get_role(team['role_id']) else 'Role N/A'})" for team in team_matches[:5]])
        if len(team_matches) > 5: team_summary_val += f"\n... and {len(team_matches)-5} more."
        embed.add_field(name=f"Detected Teams ({len(team_matches)})", value=team_summary_val or "None", inline=False)
        # Role summary (top match for each type)
        role_summary_parts = []
        for r_key, r_matches in role_matches.items():
            if r_matches: role_summary_parts.append(f"• **{role_type_map[r_key]}**: {r_matches[0]['name']} ({r_matches[0]['similarity']:.0%})")
        embed.add_field(name="Top Role Matches (by type)", value="\n".join(role_summary_parts) or "None", inline=False)
        # Channel summary (top match for each type)
        chan_summary_parts = []
        for c_key, c_matches in channel_matches.items():
            if c_matches: chan_summary_parts.append(f"• **{c_key.replace('_',' ').title()}**: #{c_matches[0]['name']} ({c_matches[0]['similarity']:.0%})")
        embed.add_field(name="Top Channel Matches (by type)", value="\n".join(chan_summary_parts) or "None", inline=False)

        embed.set_footer(text=f"Using threshold: {threshold:.0%}. Adjust if matches are poor.")
        await interaction.followup.send(embed=embed, view=view, ephemeral=True)


    @app_commands.command(name="settings", description="View the current bot configuration for this server")
    @app_commands.default_permissions(administrator=True)
    async def settings(self, interaction: discord.Interaction):
        if not await is_admin(interaction.user):
            await interaction.response.send_message(embed=EmbedBuilder.error("Permission Denied", "Only admins can use this."),ephemeral=True)
            return

        config = get_server_config(interaction.guild.id)
        embed = discord.Embed(title="🛠️ Server Configuration Overview", description="Current bot settings for this server.", color=discord.Color.blue())

        # Permission Roles
        permission_settings = config.get("permission_settings", {})
        roles_text_parts = []
        default_permission_keys = get_default_config().get("permission_settings", {}).keys()
        for key in sorted(list(default_permission_keys)): # Sort for consistent order
            display_name = key.replace("_roles", "").replace("_", " ").title() + " Roles"
            role_ids = permission_settings.get(key, [])
            role_mentions = [interaction.guild.get_role(rid).mention for rid in role_ids if interaction.guild.get_role(rid)]
            roles_text_parts.append(f"**{display_name}:** {', '.join(role_mentions) if role_mentions else 'Not set'}")
        embed.add_field(name="🎭 Permission Roles", value="\n".join(roles_text_parts) or "No roles configured.", inline=False)

        # Configured Channels
        log_channels = config.get("log_channels", {})
        ann_channels = config.get("announcement_channels", {})
        notif_settings = config.get("notification_settings", {}) # For reminders_channel_id
        channels_text_parts = []
        # Consistent display order for channels
        channel_keys_ordered = list(get_default_config().get("log_channels",{}).keys()) + \
                               list(get_default_config().get("announcement_channels",{}).keys()) + \
                               ["reminders_channel_id"]
        for key in sorted(list(set(channel_keys_ordered))): # Unique keys, sorted
            channel_id = None
            display_key_name = key.replace("_channel_id","").replace("_channel","").replace("_", " ").title() + " Channel"
            if key == "reminders_channel_id": channel_id = notif_settings.get(key)
            elif key in ann_channels: channel_id = ann_channels.get(key)
            elif key in log_channels: channel_id = log_channels.get(key)

            channel = interaction.guild.get_channel(channel_id) if channel_id else None
            channels_text_parts.append(f"**{display_key_name}:** {channel.mention if channel else 'Not set'}")
        embed.add_field(name="📝 Configured Channels", value="\n".join(channels_text_parts) or "No channels configured.", inline=False)

        # Team Configuration Summary
        team_data = config.get("team_data", {})
        default_roster_cap_val = config.get("roster_cap", DEFAULT_ROSTER_CAP)
        teams_text_parts = [f"**Global Roster Cap:** {default_roster_cap_val}"]
        sorted_team_names = sorted(list(team_data.keys()))

        for team_name in sorted_team_names[:10]: # Display first 10 teams
            data = team_data[team_name]
            role = interaction.guild.get_role(data.get("role_id"))
            roster_cap = data.get("roster_cap", f"Global ({default_roster_cap_val})")
            teams_text_parts.append(f"• {data.get('emoji','')} **{team_name}**: {role.mention if role else 'N/A'} (Cap: {roster_cap})")
        if len(sorted_team_names) > 10: teams_text_parts.append(f"... and {len(sorted_team_names) - 10} more teams.")
        if not team_data: teams_text_parts.append("No teams configured. Use `/addteam` or `/autosetup`.")
        embed.add_field(name=f"🏆 Teams (Total: {len(team_data)})", value="\n".join(teams_text_parts), inline=False)

        # Notification Settings Summary
        notif_display = config.get("notification_settings", {})
        notif_text_parts = [ f"**{k.replace('_',' ').title()}:** {'✅ On' if v else '❌ Off'}"
            for k, v in notif_display.items() if isinstance(v, bool) ] # Display only boolean toggles
        embed.add_field(name="🔔 Game Notifications (`/gamealerts`)", value="\n".join(notif_text_parts) or "Defaults active.", inline=False)

        embed.set_footer(text=f"Server ID: {interaction.guild.id} • Use /setup or specific commands to modify.")
        await interaction.response.send_message(embed=embed, ephemeral=True)


    async def send_setup_page(self, interaction: discord.Interaction, page_index: int):
        # This method is called by SetupPageView buttons
        if interaction.user.id not in self.active_setup_sessions:
            await interaction.followup.send(embed=EmbedBuilder.error("Session Expired", "Your setup session has expired. Run /setup again."),ephemeral=True)
            return

        session = self.active_setup_sessions[interaction.user.id]
        session["current_page"] = page_index # Update current page in session
        setup_pages_list = session["setup_pages"] # Get pages from session

        if not 0 <= page_index < len(setup_pages_list):
            await interaction.followup.send(embed=EmbedBuilder.error("Invalid Page", "Requested page does not exist."),ephemeral=True)
            return

        page_data_dict = setup_pages_list[page_index]
        embed = discord.Embed(title=f"{page_data_dict['icon']} {page_data_dict['title']}", description=page_data_dict["description"], color=page_data_dict["color"])

        # guild_config is the live config from the session
        guild_config_live = session["config"]
        key_mapping_dict = session.get("key_mapping", {})

        for field_item in page_data_dict["fields"]:
            field_key_page = field_item["key"]
            current_display_value = "Not set"

            if field_item["type"] == "role":
                # Key for permission_settings is like "admin_roles", "gm_roles"
                # field_key_page from setup_pages is like "admin_role", "gm_role"
                role_list_key_in_perms = f"{field_key_page.replace('_role', '')}_roles"
                permission_settings_dict = guild_config_live.get("permission_settings", {})
                role_ids_list = permission_settings_dict.get(role_list_key_in_perms, [])
                if role_ids_list:
                    roles_mentions_list = [interaction.guild.get_role(rid).mention for rid in role_ids_list if interaction.guild.get_role(rid)]
                    if roles_mentions_list: current_display_value = "\n".join([f"• {r}" for r in roles_mentions_list])

            elif field_item["type"] == "channel":
                # Use key_mapping_dict to find the actual config key for this channel field
                actual_config_key = key_mapping_dict.get(field_key_page)
                channel_id_val = None
                if actual_config_key:
                    # Determine which part of config stores this channel
                    if field_key_page == "reminders_channel": # Special case, stored in notification_settings
                        channel_id_val = guild_config_live.get("notification_settings", {}).get(actual_config_key)
                    elif field_key_page in ["announcements_channel", "free_agency_channel"]: # Stored in announcement_channels
                        channel_id_val = guild_config_live.get("announcement_channels", {}).get(actual_config_key)
                    else: # Assumed to be in log_channels
                        channel_id_val = guild_config_live.get("log_channels", {}).get(actual_config_key)

                if channel_id_val:
                    channel_obj = interaction.guild.get_channel(channel_id_val)
                    if channel_obj: current_display_value = channel_obj.mention

            elif field_item["type"] == "team": # For roster caps page
                team_data_dict = guild_config_live.get("team_data", {})
                global_cap = guild_config_live.get("roster_cap", DEFAULT_ROSTER_CAP)
                display_parts = [f"**Global Default Cap:** {global_cap}\n\n**Team Specific Caps:**"]
                sorted_teams = sorted(list(team_data_dict.keys()))
                if sorted_teams:
                    for team_n in sorted_teams[:10]: # Show first 10
                        team_specific_cap = team_data_dict[team_n].get('roster_cap', f"Uses Global ({global_cap})")
                        display_parts.append(f"• {team_data_dict[team_n].get('emoji','')} {team_n}: {team_specific_cap}")
                    if len(sorted_teams) > 10: display_parts.append(f"... and {len(sorted_teams) - 10} more teams.")
                else:
                    display_parts.append("No teams configured for specific caps.")
                current_display_value = "\n".join(display_parts)

            else: # Fallback for simple top-level keys if any
                 current_display_value = str(guild_config_live.get(field_key_page, 'Not set'))

            embed.add_field(name=field_item['name'], value=f"{field_item['description']}\n\n**Current:** {current_display_value}", inline=field_item.get("inline", True))

        embed.set_footer(text=f"Page {page_index + 1}/{len(setup_pages_list)}")
        view = SetupPageView(self, page_data_dict, session, interaction.guild, interaction.user.id)

        # Ensure interaction.edit_original_response is used if already deferred/responded by button
        if interaction.response.is_done():
            await interaction.edit_original_response(embed=embed, view=view)
        else: # Should be from initial /setup call
            await interaction.followup.send(embed=embed, view=view, ephemeral=True)


    @app_commands.command(name="setup", description="Configure the bot for your server (interactive)")
    @app_commands.default_permissions(administrator=True)
    async def setup(self, interaction: discord.Interaction):
        if not await is_admin(interaction.user):
            await interaction.response.send_message(embed=EmbedBuilder.error("Permission Denied", "Only admins can use this."),ephemeral=True)
            return

        self.cleanup_sessions() # Clean old sessions before starting a new one
        if interaction.user.id in self.active_setup_sessions:
            await interaction.response.send_message(embed=EmbedBuilder.warning("Session Active", "You already have an active setup session. Please complete or cancel it, or wait for it to expire (30 mins)."),ephemeral=True)
            return

        try:
            live_config_from_db = get_server_config(interaction.guild.id)
        except Exception as e:
            logger.error(f"Failed to load server config for guild {interaction.guild.id} in /setup: {e}", exc_info=True)
            await interaction.response.send_message(embed=EmbedBuilder.error("Config Load Error", "Failed to load config. Try again."),ephemeral=True)
            return

        session_data = {
            "config": live_config_from_db, # This is the object that will be modified
            "timestamp": time.time(),
            "current_page": 0,
            # key_mapping helps map UI field keys to their actual location in the config structure
            "key_mapping": {
                # Log Channels (under "log_channels")
                "transactions_channel": "transactions", "games_channel": "games",
                "suspensions_channel": "suspensions", "general_channel": "general",
                "results_channel": "results", "owners_channel": "owners",
                # Announcement Channels (under "announcement_channels")
                "announcements_channel": "announcements", # Note: default_config has "announcements_channel_id"
                "free_agency_channel": "free_agency", # Check if this should be under log_channels or announcement_channels
                # Notification Settings (under "notification_settings")
                "reminders_channel": "reminders_channel_id",
            }
        }

        # Define setup pages - THIS IS WHERE NEW ROLES WILL BE ADDED
        setup_pages = [
            {"title": "Core Roles", "description": "Essential roles for bot operation and league management.","icon": "👑","color": discord.Color.gold().value,"fields": [
                {"name": "Admin Role", "description": "Full administrative privileges for bot commands.", "type": "role", "key": "admin"}, # "admin" becomes "admin_roles"
                {"name": "Moderator Role", "description": "Moderation privileges for bot commands.", "type": "role", "key": "moderator"},
            ]},
            {"title": "Team Staff Roles", "description": "Roles for team management personnel.","icon": "🛠️","color": discord.Color.teal().value,"fields": [
                {"name": "General Manager Role", "description": "Role for General Managers.", "type": "role", "key": "gm"},
                {"name": "Head Coach Role", "description": "Role for Head Coaches.", "type": "role", "key": "hc"},
                {"name": "Assistant Coach Role", "description": "Role for Assistant Coaches.", "type": "role", "key": "ac"},
                {"name": "Franchise Owner Role", "description": "Role for Franchise Owners.", "type": "role", "key": "fo"},
                 {"name": "Manage Teams Role", "description": "Users with this role can manage multiple teams (e.g. commissioners).", "type": "role", "key": "manage_teams"},
            ]},
            {"title": "Player & Community Roles", "description": "Roles for players and community engagement.","icon": "👤","color": discord.Color.green().value,"fields": [
                {"name": "Candidate Role", "description": "Role for prospective players or candidates.", "type": "role", "key": "candidate"},
                {"name": "Referee Role", "description": "Role for official Referees.", "type": "role", "key": "referee"},
                {"name": "Streamer Role", "description": "Role for official league Streamers.", "type": "role", "key": "streamer"},
                # ADD NEW ROLES HERE:
                {"name": "Blacklisted Role", "description": "Users with this role are blacklisted from general bot interactions.", "type": "role", "key": "blacklisted"},
                {"name": "Suspension Role", "description": "Role assigned to suspended users.", "type": "role", "key": "suspension"},
                {"name": "Ticket Blacklisted Role", "description": "Users with this role cannot create support tickets.", "type": "role", "key": "ticket_blacklisted"},
                {"name": "Free Agent Role", "description": "Role designating a player as a Free Agent.", "type": "role", "key": "free_agent"},
            ]},
            {"title": "Log Channels Setup", "description": "Channels for various bot and league activity logs.","icon": "📝","color": discord.Color.light_grey().value,"fields": [
                {"name": "Transactions Log", "description": "Logs signings, releases, trades.", "type": "channel", "key": "transactions_channel"},
                {"name": "Games Log", "description": "Logs game scheduling, score reports.", "type": "channel", "key": "games_channel"},
                {"name": "Suspensions Log", "description": "Logs player suspensions and appeals.", "type": "channel", "key": "suspensions_channel"},
                {"name": "General Log", "description": "General bot operational logs.", "type": "channel", "key": "general_channel"},
            ]},
            {"title": "Results & Announcements Channels", "description": "Channels for game results and league news.","icon": "📢","color": discord.Color.blurple().value,"fields": [
                {"name": "Results Log/Channel", "description": "Channel where game results are posted.", "type": "channel", "key": "results_channel"},
                {"name": "Free Agency Announcements", "description": "Channel for free agency news.", "type": "channel", "key": "free_agency_channel"}, # Ensure key_mapping reflects where this is stored
                {"name": "Main Announcements Channel", "description": "Primary channel for league announcements.", "type": "channel", "key": "announcements_channel"},
                {"name": "Game Reminders Channel", "description": "Channel for automated game reminders.", "type": "channel", "key": "reminders_channel"},
            ]},
            {"title": "Specialized Channels","description": "Channels for specific functions like owner discussions.","icon": "🔒","color": discord.Color.dark_grey().value,"fields": [
                 {"name": "Owners Channel", "description": "Private channel for team owners/GMs.", "type": "channel", "key": "owners_channel"},
            ]},
            {"title": "Team Roster Caps", "description": "Global and team-specific maximum player limits.","icon": "🧢","color": discord.Color.orange().value,"fields": [
                {"name": "Team Roster Caps", "description": "Set global default and team-specific caps.", "type": "team", "key": "team_roster_caps_config"}, # Key "team_data" was used before, make it more specific for UI if needed
            ]},
        ]
        session_data["setup_pages"] = setup_pages
        session_data["total_pages"] = len(setup_pages)

        self.active_setup_sessions[interaction.user.id] = session_data

        await interaction.response.defer(ephemeral=True) # Defer initial response
        await self.send_setup_page(interaction, 0) # Send first page using followup


    @app_commands.command(name="setchannel", description="Assign a channel to a specific function (log, announcement, etc.)")
    @app_commands.default_permissions(administrator=True)
    @app_commands.autocomplete(log_type=SetupCommands.log_type_autocomplete) # Use class method for autocomplete
    async def setchannel(self, interaction: discord.Interaction, log_type: str, channel: discord.TextChannel):
        if not await is_admin(interaction.user):
            await interaction.response.send_message(embed=EmbedBuilder.error("Permission Denied", "Only admins can use this."),ephemeral=True)
            return

        # log_type here is the actual key used in config (e.g., "transactions", "reminders_channel_id")
        # Validation against defined keys in default_config
        default_conf = get_default_config()
        valid_log_channel_keys = list(default_conf.get("log_channels", {}).keys())
        valid_ann_channel_keys = list(default_conf.get("announcement_channels", {}).keys())
        # Special case for reminders_channel_id under notification_settings
        is_reminders_channel = log_type == "reminders_channel_id"

        if not (log_type in valid_log_channel_keys or log_type in valid_ann_channel_keys or is_reminders_channel):
            all_valid = sorted(valid_log_channel_keys + valid_ann_channel_keys + (["reminders_channel_id"] if "reminders_channel_id" not in valid_log_channel_keys + valid_ann_channel_keys else []))
            await interaction.response.send_message(embed=EmbedBuilder.error("Invalid Type", f"Type must be one of: {', '.join(all_valid)}"), ephemeral=True)
            return

        if not channel.permissions_for(interaction.guild.me).send_messages:
            await interaction.response.send_message(embed=EmbedBuilder.error("Permissions Missing", f"Bot lacks Send Messages permission in {channel.mention}."),ephemeral=True)
            return

        config = get_server_config(interaction.guild.id)
        old_channel_id = None
        action_description = ""

        if is_reminders_channel:
            notif_settings = config.setdefault("notification_settings", {})
            old_channel_id = notif_settings.get(log_type)
            notif_settings[log_type] = channel.id
            action_description = f"Game Reminders channel to {channel.mention}"
        elif log_type in valid_ann_channel_keys:
            ann_channels = config.setdefault("announcement_channels", {})
            old_channel_id = ann_channels.get(log_type)
            ann_channels[log_type] = channel.id
            action_description = f"{log_type.replace('_',' ').title()} channel to {channel.mention}"
        else: # Must be a log_channel
            log_channels = config.setdefault("log_channels", {})
            old_channel_id = log_channels.get(log_type)
            log_channels[log_type] = channel.id
            action_description = f"{log_type.replace('_',' ').title()} Log channel to {channel.mention}"

        if old_channel_id and old_channel_id != channel.id:
            old_ch_obj = interaction.guild.get_channel(old_channel_id)
            action_description += f" (was {old_ch_obj.mention if old_ch_obj else 'not set or invalid'})"
        elif old_channel_id == channel.id:
             await interaction.response.send_message(embed=EmbedBuilder.info("No Change", f"{action_description} was already set."),ephemeral=True)
             return


        save_guild_config(interaction.guild.id, config)
        await log_action(interaction.guild, "SETUP", interaction.user, f"Set {action_description}", "setchannel_cmd")
        await interaction.response.send_message(embed=EmbedBuilder.success("Channel Assigned", f"Successfully set {action_description}."), ephemeral=True)


    @app_commands.command(name="setrole", description="Assign a role to a permission type (e.g., admin, gm)")
    @app_commands.default_permissions(administrator=True)
    @app_commands.autocomplete(role_type=SetupCommands.role_type_autocomplete) # Use class method
    async def setrole(self, interaction: discord.Interaction, role_type: str, role: discord.Role, action: Optional[str] = "add"):
        if not await is_admin(interaction.user):
            await interaction.response.send_message(embed=EmbedBuilder.error("Permission Denied", "Only admins can use this."),ephemeral=True)
            return

        # role_type here is the simple key like "admin", "gm", not "admin_roles"
        # Validation against defined keys in default_config.permission_settings
        default_perm_settings = get_default_config().get("permission_settings", {})
        if f"{role_type}_roles" not in default_perm_settings:
            valid_simple_types = sorted([k.replace("_roles","") for k in default_perm_settings.keys()])
            await interaction.response.send_message(embed=EmbedBuilder.error("Invalid Role Type", f"Type must be one of: {', '.join(valid_simple_types)}"), ephemeral=True)
            return
        if action.lower() not in ["add", "remove"]:
            await interaction.response.send_message(embed=EmbedBuilder.error("Invalid Action", "Action must be 'add' or 'remove'."), ephemeral=True)
            return

        config = get_server_config(interaction.guild.id)
        permission_settings = config.setdefault("permission_settings", {})
        role_list_key_actual = f"{role_type.lower()}_roles" # Actual key in config
        role_list_for_type = permission_settings.setdefault(role_list_key_actual, [])

        response_message = ""
        log_detail = ""

        if action.lower() == "add":
            if role.id not in role_list_for_type:
                role_list_for_type.append(role.id)
                response_message = f"Added {role.mention} to {role_type.title()} roles."
                log_detail = f"Added role {role.name} ({role.id}) to {role_list_key_actual}"
            else:
                response_message = f"{role.mention} is already in {role_type.title()} roles."
        elif action.lower() == "remove":
            if role.id in role_list_for_type:
                role_list_for_type.remove(role.id)
                response_message = f"Removed {role.mention} from {role_type.title()} roles."
                log_detail = f"Removed role {role.name} ({role.id}) from {role_list_key_actual}"
            else:
                response_message = f"{role.mention} was not found in {role_type.title()} roles."

        if log_detail: # Only save and log if a change was made or attempted meaningfully
            save_guild_config(interaction.guild.id, config)
            await log_action(interaction.guild, "SETUP", interaction.user, log_detail, "setrole_cmd")

        await interaction.response.send_message(embed=EmbedBuilder.success("Role Update", response_message) if log_detail else EmbedBuilder.info("No Change", response_message), ephemeral=True)


    @app_commands.command(name="addteam", description="Add a new team to the league (creates role or uses existing)")
    @app_commands.default_permissions(administrator=True)
    @app_commands.autocomplete(role_id_or_new=SetupCommands.addteam_role_autocomplete) # Use class method
    async def addteam(self, interaction: discord.Interaction, team_name: str, role_id_or_new: str, emoji: str = "🏆"):
        if not await is_admin(interaction.user):
            await interaction.response.send_message(embed=EmbedBuilder.error("Permission Denied", "Only admins can use this."),ephemeral=True)
            return

        config = get_server_config(interaction.guild.id)
        team_data = config.setdefault("team_data", {})
        team_roles_legacy = config.setdefault("team_roles", {}) # Also update legacy if it's used

        if team_name in team_data or team_name in team_roles_legacy:
            await interaction.response.send_message(embed=EmbedBuilder.error("Team Exists", f"Team '{team_name}' already exists."),ephemeral=True)
            return

        role_obj = None
        try:
            if role_id_or_new.lower() == "new":
                if not interaction.guild.me.guild_permissions.manage_roles: raise ValueError("Bot lacks 'Manage Roles' permission to create new role.")
                role_obj = await interaction.guild.create_role(name=team_name, color=discord.Color.random(), reason=f"Team role for {team_name} by {interaction.user}")
            else:
                role_obj = interaction.guild.get_role(int(role_id_or_new))
                if not role_obj: raise ValueError("Selected role not found.")
                # Add checks for role hierarchy/permissions if necessary
                if role_obj.permissions.administrator: raise ValueError("Cannot use an admin role as a team role.")
                if interaction.user.id != interaction.guild.owner_id and role_obj >= interaction.user.top_role :
                    raise ValueError("Cannot assign a role higher than or equal to your highest role (unless server owner).")

            global_roster_cap = config.get("roster_cap", DEFAULT_ROSTER_CAP)
            team_data[team_name] = {"role_id": role_obj.id, "emoji": emoji, "roster_cap": global_roster_cap, "name": team_name} # Store name too
            team_roles_legacy[team_name] = role_obj.id # Update legacy map

            save_guild_config(interaction.guild.id, config)

            await log_action(interaction.guild, "SETUP", interaction.user, f"Team '{team_name}' added. Role: {role_obj.name}, Emoji: {emoji}, Cap: Global ({global_roster_cap})", "addteam_cmd")
            await interaction.response.send_message(embed=EmbedBuilder.success("Team Added", f"Team {team_name} {emoji} added with role {role_obj.mention}! Roster Cap set to global default ({global_roster_cap})."),ephemeral=True)
        except ValueError as ve: await interaction.response.send_message(embed=EmbedBuilder.error("Invalid Input", str(ve)), ephemeral=True)
        except discord.Forbidden: await interaction.response.send_message(embed=EmbedBuilder.error("Permissions Error", "Bot lacks permissions for role operation."),ephemeral=True)
        except Exception as e:
            logger.error(f"Error in /addteam: {e}", exc_info=True)
            await interaction.response.send_message(embed=EmbedBuilder.error("Error", str(e)), ephemeral=True)


    @app_commands.command(name="removeteam", description="Remove a team from the league configuration")
    @app_commands.default_permissions(administrator=True)
    @app_commands.autocomplete(team_name=SetupCommands.team_autocomplete) # Use class method
    async def removeteam(self, interaction: discord.Interaction, team_name: str):
        if not await is_admin(interaction.user):
            await interaction.response.send_message(embed=EmbedBuilder.error("Permission Denied", "Only admins can use this."),ephemeral=True)
            return

        config = get_server_config(interaction.guild.id)
        team_data_entry = config.get("team_data", {}).get(team_name)
        team_role_legacy_entry = config.get("team_roles", {}).get(team_name)

        if not team_data_entry and not team_role_legacy_entry:
            await interaction.response.send_message(embed=EmbedBuilder.error("Team Not Found", f"Team '{team_name}' not found in config."),ephemeral=True)
            return

        # Prefer role_id from team_data if available
        role_id_to_check = team_data_entry.get("role_id") if team_data_entry else team_role_legacy_entry

        view = TeamRemoveConfirmationView(self, config, interaction.guild.id, team_name, role_id_to_check)
        embed_msg = discord.Embed(title="⚠️ Confirm Team Removal", description=f"Are you sure you want to remove team '{team_name}' from the configuration?",color=discord.Color.orange())
        embed_msg.add_field(name="Impact", value="This removes the team from bot configuration. The associated role can optionally be deleted.", inline=False)
        await interaction.response.send_message(embed=embed_msg, view=view, ephemeral=True)


    @app_commands.command(name="configureteam", description="Configure an existing team's role, emoji, or roster cap")
    @app_commands.default_permissions(administrator=True)
    @app_commands.autocomplete(team_name=SetupCommands.team_autocomplete, role_id_or_new=SetupCommands.addteam_role_autocomplete) # Use class method
    async def configureteam(self, interaction: discord.Interaction, team_name: str,
                            role_id_or_new: Optional[str] = None,
                            emoji: Optional[str] = None,
                            roster_cap: Optional[int] = None):
        if not await is_admin(interaction.user):
            await interaction.response.send_message(embed=EmbedBuilder.error("Permission Denied", "Only admins can use this."),ephemeral=True)
            return

        config = get_server_config(interaction.guild.id)
        team_data = config.setdefault("team_data", {})
        team_roles_legacy = config.setdefault("team_roles", {})

        if team_name not in team_data and team_name not in team_roles_legacy:
            await interaction.response.send_message(embed=EmbedBuilder.error("Team Not Found", f"Team '{team_name}' not found."),ephemeral=True)
            return

        # Ensure team_data entry exists and is a dict, using legacy role_id if needed
        current_team_info = team_data.get(team_name)
        if not isinstance(current_team_info, dict): # If only in legacy or malformed
            legacy_role_id = team_roles_legacy.get(team_name)
            current_team_info = {"role_id": legacy_role_id, "emoji": "🏆", "name": team_name} # Create a basic entry
            if legacy_role_id is None: # Truly doesn't exist meaningfully
                 await interaction.response.send_message(embed=EmbedBuilder.error("Team Data Error", f"Team '{team_name}' has inconsistent data. Try removing and re-adding."),ephemeral=True)
                 return

        changes_made = []
        new_role_id_int = current_team_info.get("role_id") # Start with current
        new_role_obj = interaction.guild.get_role(new_role_id_int) if new_role_id_int else None

        if role_id_or_new:
            try:
                if role_id_or_new.lower() == "new":
                    if not interaction.guild.me.guild_permissions.manage_roles: raise ValueError("Bot lacks 'Manage Roles' to create.")
                    new_role_obj = await interaction.guild.create_role(name=team_name, color=discord.Color.random(), reason=f"Role for {team_name} by {interaction.user} via /configureteam")
                else:
                    new_role_obj = interaction.guild.get_role(int(role_id_or_new))
                    if not new_role_obj: raise ValueError("Selected role not found.")
                    if new_role_obj.permissions.administrator: raise ValueError("Admin role cannot be team role.")
                    if interaction.user.id != interaction.guild.owner_id and new_role_obj >= interaction.user.top_role:
                        raise ValueError("Cannot assign role higher than yours (unless server owner).")

                if new_role_obj.id != current_team_info.get("role_id"):
                    current_team_info["role_id"] = new_role_obj.id
                    team_roles_legacy[team_name] = new_role_obj.id # Update legacy too
                    changes_made.append(f"Role set to {new_role_obj.mention}")
            except ValueError as ve: return await interaction.response.send_message(embed=EmbedBuilder.error("Role Error", str(ve)), ephemeral=True)
            except discord.Forbidden: return await interaction.response.send_message(embed=EmbedBuilder.error("Permissions Error", "Bot lacks permissions for role operation."),ephemeral=True)

        if emoji and emoji != current_team_info.get("emoji"):
            current_team_info["emoji"] = emoji
            changes_made.append(f"Emoji set to {emoji}")

        if roster_cap is not None:
            if not 1 <= roster_cap <= 999: return await interaction.response.send_message(embed=EmbedBuilder.error("Invalid Cap", "Roster cap must be 1-999."),ephemeral=True)
            current_team_info["roster_cap"] = roster_cap
            changes_made.append(f"Roster cap set to {roster_cap}")

        current_team_info.setdefault("name", team_name) # Ensure name is in team_data
        current_team_info.setdefault("emoji", "🏆") # Ensure emoji exists
        current_team_info.setdefault("roster_cap", config.get("roster_cap", DEFAULT_ROSTER_CAP)) # Ensure cap exists

        if not changes_made:
            await interaction.response.send_message(embed=EmbedBuilder.info("No Changes", f"No changes specified for team {team_name}."),ephemeral=True)
            return

        team_data[team_name] = current_team_info # Ensure the updated dict is set back
        save_guild_config(interaction.guild.id, config)

        log_msg = f"Team '{team_name}' configured: {', '.join(changes_made)}."
        await log_action(interaction.guild, "SETUP", interaction.user, log_msg, "configureteam_cmd")

        final_role_mention = new_role_obj.mention if new_role_obj else "Not set"
        final_emoji = current_team_info['emoji']
        final_cap = current_team_info['roster_cap']
        await interaction.response.send_message(embed=EmbedBuilder.success("Team Configured", f"Team {team_name} updated!\n" + "\n".join(f"• {change}" for change in changes_made) + f"\n\nCurrent: Role {final_role_mention}, Emoji {final_emoji}, Cap {final_cap}"),ephemeral=True)

    # --- Autocomplete Methods (Static or Class methods if they don't need self) ---
    @staticmethod
    async def addteam_role_autocomplete(interaction: discord.Interaction, current: str) -> List[app_commands.Choice[str]]:
        if not interaction.guild: return []
        guild_roles = sorted(interaction.guild.roles, key=lambda r: r.position, reverse=True)
        filtered_roles = [r for r in guild_roles if r.name != "@everyone" and (current.lower() in r.name.lower() if current else True)]
        role_matches = [app_commands.Choice(name=r.name, value=str(r.id)) for r in filtered_roles[:24]] # Limit to 24 to leave space for "new"
        return [app_commands.Choice(name="✨ Create New Role", value="new")] + role_matches

    @staticmethod
    async def log_type_autocomplete(interaction: discord.Interaction, current: str) -> List[app_commands.Choice[str]]:
        default_conf = get_default_config() # Use the function directly
        log_channel_keys = list(default_conf.get("log_channels", {}).keys())
        ann_channel_keys = list(default_conf.get("announcement_channels", {}).keys())
        # reminders_channel_id is special, directly under notification_settings
        all_configurable_types = sorted(list(set(log_channel_keys + ann_channel_keys + ["reminders_channel_id"])))

        choices = []
        for key_val in all_configurable_types:
            display_name = key_val.replace("_channel_id","").replace("_channel","").replace("_", " ").title()
            if current.lower() in display_name.lower() or current.lower() in key_val.lower():
                choices.append(app_commands.Choice(name=display_name, value=key_val))
        return choices[:25]

    @staticmethod
    async def role_type_autocomplete(interaction: discord.Interaction, current: str) -> List[app_commands.Choice[str]]:
        default_perms = get_default_config().get("permission_settings", {})
        # Value is the key in permission_settings (e.g., "admin_roles"), name is user-friendly
        choices = []
        for key_val in default_perms.keys():
            simple_key = key_val.replace("_roles", "") # e.g., "admin"
            display_name = simple_key.replace("_", " ").title() # e.g., "Admin"
            if current.lower() in display_name.lower() or current.lower() in simple_key.lower():
                choices.append(app_commands.Choice(name=display_name, value=simple_key))
        return sorted(choices, key=lambda c: c.name)[:25]


class GameAlertsView(discord.ui.View):
    def __init__(self, bot, guild_id: int, guild_config_ref: Dict): # Pass full guild_config reference
        super().__init__(timeout=300)
        self.bot = bot
        self.guild_id = guild_id
        self.guild_config = guild_config_ref # This is the live config object
        # self.notification_settings is a direct reference to the part of guild_config
        self.notification_settings = self.guild_config.setdefault("notification_settings", get_default_config()["notification_settings"].copy())
        self._init_buttons()

    def _init_buttons(self):
        self.clear_items() # Clear any existing items before re-adding
        # Use default config structure for button definitions and default states
        default_notif_settings_template = get_default_config().get("notification_settings",{})

        # First row: General toggles
        general_toggles = ["channel_notifications", "dm_notifications", "staff_notifications", "game_reminders"]
        for i, key in enumerate(general_toggles):
            if key not in default_notif_settings_template: continue # Skip if somehow not in default
            label = key.replace("_", " ").title()
            enabled = self.notification_settings.get(key, default_notif_settings_template.get(key, True))
            button = discord.ui.Button(label=label, style=discord.ButtonStyle.success if enabled else discord.ButtonStyle.danger, custom_id=f"toggle_{key}", row=0)
            button.callback = self.button_callback
            self.add_item(button)

        # Subsequent rows: Specific reminder time toggles
        reminder_time_keys = [k for k in default_notif_settings_template.keys() if k.startswith("reminder_") and k not in ["reminders_channel_id"]]
        reminder_time_keys.sort() # Sort for consistent order
        current_row = 1
        items_in_row = 0
        for key in reminder_time_keys:
            if items_in_row >= 3: # Max 3-4 reminder toggles per row for neatness
                current_row += 1
                items_in_row = 0
            if current_row > 4 : break # Limit rows for reminder toggles

            label = key.replace("reminder_", "").replace("h", " Hours").replace("m", " Mins").replace("_", " ").title()
            enabled = self.notification_settings.get(key, default_notif_settings_template.get(key, True))
            button = discord.ui.Button(label=label, style=discord.ButtonStyle.success if enabled else discord.ButtonStyle.secondary, custom_id=f"toggle_{key}", row=current_row)
            button.callback = self.button_callback
            self.add_item(button)
            items_in_row +=1

        # Reminders Channel Select
        reminders_channel_select = discord.ui.ChannelSelect(
            placeholder="Select Game Reminders Channel",
            custom_id="select_reminders_channel_id", # Matches a potential key in notification_settings
            channel_types=[discord.ChannelType.text],
            min_values=0, max_values=1, row=max(current_row + 1, 2) # Ensure it's on a new row after toggles
        )
        reminders_channel_select.callback = self.channel_select_callback
        self.add_item(reminders_channel_select)

        save_button = discord.ui.Button(label="Save Settings", style=discord.ButtonStyle.primary, custom_id="save_notification_settings", row=max(current_row + 2, 3))
        save_button.callback = self.save_button_callback
        self.add_item(save_button)

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if not await is_admin(interaction.user): # No need for can_use_command here
            await interaction.response.send_message(embed=EmbedBuilder.error("Permission Denied", "Only admins can modify these."),ephemeral=True)
            return False
        return True

    async def on_timeout(self):
        for item in self.children: item.disabled = True
        if hasattr(self, 'message') and self.message: # Check if message attribute exists
            try: await self.message.edit(view=self)
            except discord.NotFound: pass # Message might have been deleted
            except Exception as e: logger.warning(f"Error disabling GameAlertsView on timeout: {e}")


    async def button_callback(self, interaction: discord.Interaction):
        custom_id = interaction.data.get("custom_id")
        setting_key = custom_id.replace("toggle_", "")
        default_value_template = get_default_config().get("notification_settings",{})
        current_value = self.notification_settings.get(setting_key, default_value_template.get(setting_key, True))
        self.notification_settings[setting_key] = not current_value # Toggle
        # The change is directly on self.guild_config["notification_settings"]
        await self.update_embed(interaction) # This will re-init buttons and send edit

    async def channel_select_callback(self, interaction: discord.Interaction):
        custom_id = interaction.data.get("custom_id") # Should be "select_reminders_channel_id"
        selected_channel_id = interaction.data.get("values", [None])[0]

        # Key in notification_settings is "reminders_channel_id"
        self.notification_settings["reminders_channel_id"] = int(selected_channel_id) if selected_channel_id else None
        await self.update_embed(interaction)

    async def save_button_callback(self, interaction: discord.Interaction):
        try:
            # self.guild_config (which contains self.notification_settings) is already modified in-memory.
            save_guild_config(self.guild_id, self.guild_config) # Save the entire modified guild_config

            changes_summary = []
            default_notif_settings_template = get_default_config().get("notification_settings",{})
            for key, default_val in default_notif_settings_template.items():
                current_val = self.notification_settings.get(key, default_val)
                display_name = key.replace("_", " ").title()
                if key == "reminders_channel_id":
                    ch_obj = interaction.guild.get_channel(current_val) if current_val else None
                    changes_summary.append(f"• {display_name}: {ch_obj.mention if ch_obj else 'Not set'}")
                elif isinstance(default_val, bool):
                    changes_summary.append(f"• {display_name}: {'Enabled' if current_val else 'Disabled'}")

            await log_action(interaction.guild, "CONFIG", interaction.user, f"Updated game alerts settings. Details:\n" + "\n".join(changes_summary), "gamealerts_save")

            embed = discord.Embed(title="✅ Settings Saved", description="Game alert settings updated successfully!\n\n" + "\n".join(changes_summary), color=discord.Color.green())
            for item in self.children: item.disabled = True # Disable all buttons on save
            await interaction.response.edit_message(embed=embed, view=self)
            self.stop() # Stop the view
        except Exception as e:
            logger.error(f"Error saving game alert settings for guild {self.guild_id}: {e}", exc_info=True)
            await interaction.response.send_message(embed=EmbedBuilder.error("Save Error", str(e)), ephemeral=True) # Use followup if edit fails

    async def update_embed(self, interaction: discord.Interaction):
        # This is called after a button/select changes a setting in self.notification_settings
        embed = discord.Embed(title="🔔 Game Alerts Configuration", description="Configure game reminders and notifications.", color=discord.Color.blue())

        settings_text_parts = []
        default_config_template = get_default_config()
        default_notification_config_template = default_config_template.get("notification_settings", {})

        for key, default_val in default_notification_config_template.items():
            current_val = self.notification_settings.get(key, default_val)
            display_name = key.replace("_", " ").title()
            if key == "reminders_channel_id":
                channel_obj = interaction.guild.get_channel(current_val) if current_val else None
                settings_text_parts.append(f"**{display_name}:** {channel_obj.mention if channel_obj else 'Not set'}")
            elif isinstance(default_val, bool):
                 settings_text_parts.append(f"**{display_name}:** {'✅ Enabled' if current_val else '❌ Disabled'}")

        embed.add_field(name="Current Settings (Updated)", value="\n".join(settings_text_parts) or "No settings found.", inline=False)

        self._init_buttons() # Re-initialize buttons to reflect new states (e.g., color changes)
        await interaction.response.edit_message(embed=embed, view=self)


class RosterCapModal(discord.ui.Modal, title="Edit Roster Cap"):
    def __init__(self, cog_ref, session_config_live_ref, guild_obj, user_id_init, target_team_key, current_cap_value=None):
        super().__init__()
        self.cog = cog_ref # Reference to SetupCommands cog for active_setup_sessions
        self.session_config = session_config_live_ref # Direct reference to session["config"]
        self.guild = guild_obj
        self.user_id = user_id_init # User who initiated the /setup command
        self.target_key_or_global = target_team_key # "all_teams_global_cap" or actual team name

        self.cap_input = discord.ui.TextInput(label="New Roster Cap (1-999)") # Renamed
        self.cap_input.default = str(current_cap_value if current_cap_value is not None else self.session_config.get("roster_cap", DEFAULT_ROSTER_CAP))
        self.cap_input.placeholder = "Enter a number, e.g., 53"
        if self.target_key_or_global != "all_teams_global_cap":
             self.cap_input.label = f"Cap for Team: {self.target_key_or_global}"
        self.add_item(self.cap_input)

    async def on_submit(self, interaction: discord.Interaction):
        try:
            cap_value_int = int(self.cap_input.value)
            if not 1 <= cap_value_int <= 999: raise ValueError("Cap must be between 1 and 999.")

            log_detail_msg = ""
            success_user_msg = ""

            if self.target_key_or_global == "all_teams_global_cap":
                old_cap = self.session_config.get("roster_cap", "Not set")
                self.session_config["roster_cap"] = cap_value_int
                log_detail_msg = f"Global roster cap to {cap_value_int} (was {old_cap})."
                success_user_msg = f"Global default roster cap updated to {cap_value_int}."
            else:
                team_data_dict = self.session_config.setdefault("team_data", {})
                team_specific_conf = team_data_dict.setdefault(self.target_key_or_global, {"name": self.target_key_or_global, "emoji": "🏆"}) # Ensure team entry exists
                old_cap = team_specific_conf.get("roster_cap", f"Global ({self.session_config.get('roster_cap', DEFAULT_ROSTER_CAP)})")
                team_specific_conf["roster_cap"] = cap_value_int
                log_detail_msg = f"Roster cap for team '{self.target_key_or_global}' to {cap_value_int} (was {old_cap})."
                success_user_msg = f"Roster cap for '{self.target_key_or_global}' updated to {cap_value_int}."

            await log_action(self.guild, "SETUP (IN-SESSION)", interaction.user, f"Set {log_detail_msg}", "roster_cap_modal_submit")
            # Send ephemeral confirmation of modal change
            await interaction.response.send_message(embed=EmbedBuilder.success("Roster Cap Staged", success_user_msg + "\nChanges apply when main setup is saved."),ephemeral=True)

            # Attempt to refresh the main setup page view if possible
            # This requires getting the original interaction for the /setup command, which is complex from a modal.
            # For now, the main view will refresh on next navigation or save.
            if self.cog and self.user_id in self.cog.active_setup_sessions:
                active_session = self.cog.active_setup_sessions[self.user_id]
                original_interaction_proxy = active_session.get("interaction_proxy") # If we stored it
                if original_interaction_proxy:
                    try: # This is a placeholder for a more robust refresh mechanism
                        # This might not work as intended due to interaction lifecycle.
                        # await self.cog.send_setup_page(original_interaction_proxy, active_session["current_page"])
                        logger.debug(f"RosterCapModal: Would attempt to refresh page {active_session['current_page']} for user {self.user_id} if proxy worked.")
                    except Exception as e_refresh:
                        logger.warning(f"RosterCapModal: Failed to auto-refresh main setup page: {e_refresh}")
                else:
                     logger.debug(f"RosterCapModal: No interaction_proxy found in session to refresh main setup page for user {self.user_id}.")


        except ValueError as ve: await interaction.response.send_message(embed=EmbedBuilder.error("Invalid Input", str(ve)), ephemeral=True)
        except Exception as e:
            logger.error(f"Error in RosterCapModal on_submit: {e}", exc_info=True)
            await interaction.response.send_message(embed=EmbedBuilder.error("Error", "An unexpected error occurred in modal."),ephemeral=True)


class SetupPageView(discord.ui.View):
    def __init__(self, cog_ref, page_data_dict: Dict, session_ref: Dict, guild_obj: discord.Guild, user_id_init: int):
        super().__init__(timeout=1800) # 30 min timeout for the view
        self.cog = cog_ref
        self.page_data = page_data_dict # Current page's definition
        self.session = session_ref # Reference to active_setup_sessions[user_id]
        self.guild = guild_obj
        self.user_id = user_id_init

        # Moved config_display_names here as it's specific to this view's rendering
        self.config_display_names = {
            "admin": "Admin Role", "moderator": "Moderator Role",
            "gm": "General Manager Role", "hc": "Head Coach Role", "ac": "Assistant Coach Role",
            "fo": "Franchise Owner Role", "candidate": "Candidate Role", "referee": "Referee Role",
            "streamer": "Streamer Role", "manage_teams": "Manage Teams Role",
            # New roles to be added for display name mapping
            "blacklisted": "Blacklisted Role",
            "suspension": "Suspension Role",
            "ticket_blacklisted": "Ticket Blacklisted Role",
            "free_agent": "Free Agent Role",
            # Channels (using the key from setup_pages field definition)
            "transactions_channel": "Transactions Log", "games_channel": "Games Log",
            "suspensions_channel": "Suspensions Log", "general_channel": "General Log",
            "results_channel": "Results Log/Channel", "free_agency_channel": "Free Agency Announcements",
            "announcements_channel": "Main Announcements Channel", "reminders_channel": "Game Reminders Channel",
            "owners_channel": "Owners Channel",
            # Team Roster Caps (key from setup_pages field definition)
            "team_roster_caps_config": "Team Roster Caps",
        }
        self.create_dynamic_selects()
        self.add_navigation_buttons()

    def create_dynamic_selects(self):
        # Max 4 dynamic selects per page to keep UI clean, then navigation
        for i, field_def in enumerate(self.page_data["fields"][:4]): # Limit to 4 selects
            select_custom_id = f"setup_select_{self.session['current_page']}_{field_def['key']}" # Unique ID per page/field

            if field_def["type"] == "role":
                # Get current role(s) for this field_def["key"] (e.g., "admin")
                # The actual key in permission_settings is "admin_roles"
                perm_settings = self.session["config"].get("permission_settings", {})
                role_list_key = f"{field_def['key']}_roles" # e.g. "admin_roles"
                current_role_ids = perm_settings.get(role_list_key, [])
                default_roles = [discord.Object(id=rid) for rid in current_role_ids if isinstance(rid, int)]

                select = discord.ui.RoleSelect(placeholder=f"Select {field_def['name']}",
                                               min_values=0, max_values=1 if "manage_teams" not in field_def["key"] else 5, # Allow multiple for manage_teams_roles etc.
                                               custom_id=select_custom_id, row=i, defaults=default_roles if default_roles else None)
                select.callback = lambda inter, s=select, k=field_def['key']: self.select_callback_handler(inter, s, k, "role")
                self.add_item(select)

            elif field_def["type"] == "channel":
                mapped_key = self.session["key_mapping"].get(field_def["key"])
                current_channel_id = None
                if mapped_key:
                    if field_def["key"] == "reminders_channel": current_channel_id = self.session["config"].get("notification_settings",{}).get(mapped_key)
                    elif field_def["key"] in ["announcements_channel","free_agency_channel"]: current_channel_id = self.session["config"].get("announcement_channels",{}).get(mapped_key)
                    else: current_channel_id = self.session["config"].get("log_channels",{}).get(mapped_key)
                default_channel = [discord.Object(id=current_channel_id)] if current_channel_id else None

                select = discord.ui.ChannelSelect(placeholder=f"Select {field_def['name']}",
                                                  min_values=0, max_values=1, channel_types=[discord.ChannelType.text],
                                                  custom_id=select_custom_id, row=i, defaults=default_channel if default_channel else None)
                select.callback = lambda inter, s=select, k=field_def['key']: self.select_callback_handler(inter, s, k, "channel")
                self.add_item(select)

            elif field_def["type"] == "team": # For Roster Cap page
                team_data = self.session["config"].get("team_data", {})
                teams = sorted(list(team_data.keys()))

                team_select = discord.ui.Select(placeholder="Select Team or Global to Edit Cap", min_values=0, max_values=1, custom_id=select_custom_id, row=i)
                team_select.add_option(label="Global Default Roster Cap", value="all_teams_global_cap", emoji="🌍")
                for team_n in teams[:23]: # Max 24 options after global
                    team_emoji = team_data.get(team_n,{}).get('emoji','🔹')
                    team_select.add_option(label=f"{team_emoji} {team_n}", value=team_n)
                if len(teams) > 23: team_select.add_option(label="More teams...", value="disabled_placeholder", disabled=True)

                team_select.callback = self.roster_cap_team_select_modal_launcher # Different callback
                self.add_item(team_select)

    async def roster_cap_team_select_modal_launcher(self, interaction: discord.Interaction):
        if interaction.user.id != self.user_id:
            await interaction.response.send_message("Not your setup session.", ephemeral=True); return

        selected_target_key = interaction.data.get("values", [None])[0]
        if not selected_target_key or selected_target_key == "disabled_placeholder":
            await interaction.response.defer(); return # Ignore if placeholder or no selection

        current_cap_val = None
        if selected_target_key == "all_teams_global_cap":
            current_cap_val = self.session["config"].get("roster_cap", DEFAULT_ROSTER_CAP)
        else:
            current_cap_val = self.session["config"].get("team_data", {}).get(selected_target_key, {}).get("roster_cap", self.session["config"].get("roster_cap", DEFAULT_ROSTER_CAP))

        modal = RosterCapModal(self.cog, self.session["config"], self.guild, self.user_id, selected_target_key, current_cap_val)
        await interaction.response.send_modal(modal)
        # After modal submission, the main setup page is NOT automatically refreshed by this.
        # User needs to navigate or save to see the updated "Current:" value on the roster cap page.

    async def select_callback_handler(self, interaction: discord.Interaction, select_obj: Union[discord.ui.RoleSelect, discord.ui.ChannelSelect], field_ui_key: str, item_type: str):
        if interaction.user.id != self.user_id:
            await interaction.response.send_message("Not your setup session.", ephemeral=True); return

        live_config = self.session["config"]
        log_entry_detail = ""
        display_name_for_log = self.config_display_names.get(field_ui_key, field_ui_key.replace("_"," ").title())

        if item_type == "role":
            # field_ui_key is e.g. "admin", "gm"
            actual_config_key_in_perms = f"{field_ui_key}_roles" # e.g., "admin_roles"
            perm_settings_dict = live_config.setdefault("permission_settings", {})
            role_list_for_type = perm_settings_dict.setdefault(actual_config_key_in_perms, [])

            role_list_for_type.clear() # Assuming single role for most, or handled by max_values in select
            selected_values = select_obj.values # This is a list of Role objects
            if selected_values:
                for role_val_obj in selected_values:
                    role_list_for_type.append(role_val_obj.id)
                mentions = ", ".join([r.mention for r in selected_values])
                log_entry_detail = f"Set {display_name_for_log} to: {mentions}"
            else: # Cleared
                log_entry_detail = f"Cleared {display_name_for_log}."

        elif item_type == "channel":
            # field_ui_key is e.g. "transactions_channel", "reminders_channel"
            actual_config_key_mapped = self.session["key_mapping"].get(field_ui_key)
            selected_channel_obj = select_obj.values[0] if select_obj.values else None

            if actual_config_key_mapped:
                target_dict_path = None # e.g. "log_channels", "notification_settings"
                if field_ui_key == "reminders_channel": target_dict_path = live_config.setdefault("notification_settings", {})
                elif field_ui_key in ["announcements_channel","free_agency_channel"]: target_dict_path = live_config.setdefault("announcement_channels", {})
                else: target_dict_path = live_config.setdefault("log_channels", {})

                if selected_channel_obj:
                    target_dict_path[actual_config_key_mapped] = selected_channel_obj.id
                    log_entry_detail = f"Set {display_name_for_log} to {selected_channel_obj.mention}"
                else: # Cleared
                    target_dict_path.pop(actual_config_key_mapped, None)
                    log_entry_detail = f"Cleared {display_name_for_log}."
            else:
                logger.warning(f"Setup: No key mapping found for UI field '{field_ui_key}'. Cannot save selection.")
                log_entry_detail = f"Error: No mapping for '{field_ui_key}'. Selection not saved."

        if log_entry_detail:
            await log_action(self.guild, "SETUP (IN-SESSION)", interaction.user, log_entry_detail, "setup_select_change")

        await interaction.response.defer() # Acknowledge interaction
        # Re-render the current page to show the updated "Current:" value
        await self.cog.send_setup_page(interaction, self.session["current_page"])


    def add_navigation_buttons(self):
        # Row 4 for navigation and save
        nav_buttons_data = [
            ("⏮️ First", "first_page", discord.ButtonStyle.secondary, self.first_page_callback),
            ("◀️ Prev", "prev_page", discord.ButtonStyle.primary, self.prev_page_callback),
            ("Next ▶️", "next_page", discord.ButtonStyle.primary, self.next_page_callback),
            ("Last ⏭️", "last_page", discord.ButtonStyle.secondary, self.last_page_callback),
            ("💾 Save & Exit", "save_exit", discord.ButtonStyle.success, self.save_and_exit_callback)
        ]
        for label, custom_id, style, callback_func in nav_buttons_data:
            button = discord.ui.Button(label=label, custom_id=custom_id, style=style, row=4)
            button.callback = callback_func
            self.add_item(button)
        self._update_nav_button_states()

    def _update_nav_button_states(self):
        current_pg = self.session.get("current_page", 0)
        total_pgs = self.session.get("total_pages", 1)
        for item in self.children:
            if isinstance(item, discord.ui.Button):
                if item.custom_id == "first_page" or item.custom_id == "prev_page": item.disabled = (current_pg == 0)
                elif item.custom_id == "next_page" or item.custom_id == "last_page": item.disabled = (current_pg >= total_pgs - 1)

    async def first_page_callback(self, interaction: discord.Interaction):
        if interaction.user.id != self.user_id: await interaction.response.defer(); return
        await interaction.response.defer()
        await self.cog.send_setup_page(interaction, 0)
    async def prev_page_callback(self, interaction: discord.Interaction):
        if interaction.user.id != self.user_id: await interaction.response.defer(); return
        current_pg = self.session.get("current_page", 0)
        await interaction.response.defer()
        if current_pg > 0: await self.cog.send_setup_page(interaction, current_pg - 1)
    async def next_page_callback(self, interaction: discord.Interaction):
        if interaction.user.id != self.user_id: await interaction.response.defer(); return
        current_pg = self.session.get("current_page", 0); total_pgs = self.session.get("total_pages", 1)
        await interaction.response.defer()
        if current_pg < total_pgs - 1: await self.cog.send_setup_page(interaction, current_pg + 1)
    async def last_page_callback(self, interaction: discord.Interaction):
        if interaction.user.id != self.user_id: await interaction.response.defer(); return
        total_pgs = self.session.get("total_pages", 1)
        await interaction.response.defer()
        await self.cog.send_setup_page(interaction, total_pgs - 1)

    async def save_and_exit_callback(self, interaction: discord.Interaction):
        if interaction.user.id != self.user_id:
            await interaction.response.send_message("Not your session.", ephemeral=True); return

        try:
            # self.session["config"] holds all the live changes
            save_guild_config(self.guild.id, self.session["config"])
            await log_action(self.guild, "SETUP COMPLETE", interaction.user, "Server configuration saved via /setup interface.", "setup_save_exit")

            embed = EmbedBuilder.success("✅ Setup Saved", "Server configuration saved successfully.")
            # Add a brief summary of what was configured if possible (counts of roles/channels set)
            perm_settings = self.session["config"].get("permission_settings", {})
            roles_set_count = sum(1 for r_list in perm_settings.values() if isinstance(r_list, list) and r_list)

            log_ch_count = sum(1 for _ in self.session["config"].get("log_channels", {}).values() if _)
            ann_ch_count = sum(1 for _ in self.session["config"].get("announcement_channels", {}).values() if _)
            rem_ch_set = 1 if self.session["config"].get("notification_settings", {}).get("reminders_channel_id") else 0
            total_channels_set = log_ch_count + ann_ch_count + rem_ch_set

            teams_configured = len(self.session["config"].get("team_data", {}))

            summary_text = (f"• **{roles_set_count}** role types have assignments.\n"
                            f"• **{total_channels_set}** channel functions assigned.\n"
                            f"• **{teams_configured}** teams configured (check roster caps separately).\n")
            embed.add_field(name="Configuration Summary", value=summary_text, inline=False)
            embed.add_field(name="Next Steps", value="• Use `/addteam`, `/configureteam` for team details.\n• Use `/settings` to view all current settings.", inline=False)

            await interaction.response.edit_message(embed=embed, view=None) # Clear buttons
        except Exception as e:
            logger.error(f"Failed to save config for guild {self.guild.id} via /setup: {e}", exc_info=True)
            error_embed = EmbedBuilder.error("Save Error", "Failed to save configuration. Please try again.")
            await interaction.response.edit_message(embed=error_embed, view=None) # Clear buttons even on error
        finally:
            self.cog.active_setup_sessions.pop(self.user_id, None) # End session
            self.stop() # Stop this view


class AutoSetupConfirmationView(discord.ui.View):
    def __init__(self, bot, guild_id: int, team_matches: List[Dict], role_matches: Dict,
                 channel_matches: Dict, role_type_map: Dict, channel_config_keys: List[str], # Changed from log_types, announcement_types
                 threshold: float, setup_cog_ref):
        super().__init__(timeout=600) # Extended timeout
        self.bot, self.guild_id, self.team_matches, self.role_matches = bot, guild_id, team_matches, role_matches
        self.channel_matches, self.role_type_map, self.channel_config_keys = channel_matches, role_type_map, channel_config_keys
        self.threshold, self.cog = threshold, setup_cog_ref # setup_cog_ref is SetupCommands instance

        # Initialize selections (key: role_config_key or channel_config_key)
        self.selected_teams_by_role_id = {} # role_id -> team_match_dict
        self.selected_roles_by_type = {rt_key: None for rt_key in role_type_map.keys()} # role_type_key -> role_id
        self.selected_channels_by_type = {ct_key: None for ct_key in channel_config_keys} # channel_type_key -> channel_id

        self._add_team_select(); self._add_role_selects(); self._add_channel_selects(); self._add_control_buttons()

    def _add_team_select(self):
        if not self.team_matches: return
        # Max 25 options, so if more teams, might need multiple selects or different UI
        select = discord.ui.Select(placeholder="Select Teams to Add/Update", min_values=0, max_values=min(len(self.team_matches), 25), custom_id="autosetup_teams", row=0)
        for team_info in self.team_matches[:25]:
            select.add_option(label=f"{team_info['emoji']} {team_info['name']}", value=str(team_info["role_id"]))
        select.callback = self._team_select_callback
        self.add_item(select)

    def _add_role_selects(self):
        # Create a select for each role_type that has matches
        current_row = 1
        items_in_row = 0
        for role_config_key, display_name in self.role_type_map.items():
            top_match = self.role_matches.get(role_config_key, [None])[0] # Get top match if exists
            if not top_match: continue # Skip if no matches for this role type

            if items_in_row >= 3: current_row +=1; items_in_row = 0
            if current_row > 3: # Limit rows for roles to keep UI manageable
                logger.info(f"AutoSetup: Too many role types to display all selects. Stopping at row {current_row-1}.")
                break

            select = discord.ui.Select(placeholder=f"{display_name} (Best: {top_match['name']})", min_values=0, max_values=1, custom_id=f"autosetup_role_{role_config_key}", row=current_row)
            select.add_option(label="None (Do not set)", value="none_role_option")
            # Add top 3-5 matches for this role type
            for match_info in self.role_matches.get(role_config_key, [])[:4]: # Top 4 + None
                role_obj = self.bot.get_guild(self.guild_id).get_role(match_info["role_id"])
                if role_obj: select.add_option(label=f"{role_obj.name} ({match_info['similarity']:.0%})", value=str(match_info["role_id"]))
            select.callback = lambda inter, rck=role_config_key: self._role_select_callback(inter, rck)
            self.add_item(select)
            items_in_row +=1

    def _add_channel_selects(self):
        current_row = 4 # Start channels after roles
        items_in_row = 0
        guild = self.bot.get_guild(self.guild_id)
        for channel_config_key in self.channel_config_keys: # These are the actual keys for config
            top_match = self.channel_matches.get(channel_config_key, [None])[0]
            display_name_placeholder = channel_config_key.replace("_roles","").replace("_channel_id","").replace("_channel","").replace("_", " ").title()
            placeholder_text = f"{display_name_placeholder} Ch."
            if top_match: placeholder_text += f" (Best: #{top_match['name']})"

            if items_in_row >=2 : current_row +=1; items_in_row = 0 # Max 2 channel selects per row
            if current_row > 6 : # Limit rows for channels
                logger.info(f"AutoSetup: Too many channel types to display all selects. Stopping at row {current_row-1}.")
                break

            select = discord.ui.Select(placeholder=placeholder_text, min_values=0, max_values=1, custom_id=f"autosetup_chan_{channel_config_key}", row=current_row)
            select.add_option(label="None (Do not set)", value="none_channel_option")
            # Add top 3-5 matches + other channels
            added_channels_for_select = set()
            for match_info in self.channel_matches.get(channel_config_key, [])[:4]: # Top 4 matches
                channel_obj = guild.get_channel(match_info["channel_id"]) if guild else None
                if channel_obj:
                    select.add_option(label=f"#{channel_obj.name} ({match_info['similarity']:.0%})", value=str(match_info["channel_id"]))
                    added_channels_for_select.add(channel_obj.id)
            # Add a few more general text channels if space allows (up to 25 total options)
            if guild and len(select.options) < 25:
                for chan in guild.text_channels[:(25 - len(select.options))]: # Fill up to 25
                    if chan.id not in added_channels_for_select:
                        select.add_option(label=f"#{chan.name} (Other)", value=str(chan.id))

            select.callback = lambda inter, cck=channel_config_key: self._channel_select_callback(inter, cck)
            self.add_item(select)
            items_in_row +=1

    def _add_control_buttons(self):
        confirm = discord.ui.Button(label="Confirm & Save Selected", style=discord.ButtonStyle.success, custom_id="autosetup_confirm", row=7)
        confirm.callback = self._confirm_callback
        self.add_item(confirm)
        cancel = discord.ui.Button(label="Cancel Auto-Setup", style=discord.ButtonStyle.danger, custom_id="autosetup_cancel", row=7)
        cancel.callback = self._cancel_callback
        self.add_item(cancel)

    async def _team_select_callback(self, interaction: discord.Interaction):
        self.selected_teams_by_role_id.clear()
        for role_id_str in interaction.data.get("values", []):
            for team_match in self.team_matches:
                if str(team_match["role_id"]) == role_id_str:
                    self.selected_teams_by_role_id[int(role_id_str)] = team_match
                    break
        await interaction.response.defer() # Acknowledge, no message needed

    async def _role_select_callback(self, interaction: discord.Interaction, role_config_key: str):
        selected_val = interaction.data.get("values", [None])[0]
        self.selected_roles_by_type[role_config_key] = int(selected_val) if selected_val and selected_val != "none_role_option" else None
        await interaction.response.defer()

    async def _channel_select_callback(self, interaction: discord.Interaction, channel_config_key: str):
        selected_val = interaction.data.get("values", [None])[0]
        self.selected_channels_by_type[channel_config_key] = int(selected_val) if selected_val and selected_val != "none_channel_option" else None
        await interaction.response.defer()

    async def _confirm_callback(self, interaction: discord.Interaction):
        if not self.selected_teams_by_role_id and \
           all(v is None for v in self.selected_roles_by_type.values()) and \
           all(v is None for v in self.selected_channels_by_type.values()):
            await interaction.response.send_message(embed=EmbedBuilder.warning("No Selections", "Select items to configure or cancel."),ephemeral=True)
            return

        await interaction.response.defer(ephemeral=True) # Defer before processing
        guild = self.bot.get_guild(self.guild_id)
        config = get_server_config(self.guild_id) # Load live config

        log_summary = ["Auto-Setup Confirmed:"]

        # Apply selected teams
        if self.selected_teams_by_role_id:
            team_data_dict = config.setdefault("team_data", {})
            team_roles_legacy_dict = config.setdefault("team_roles", {}) # For legacy compatibility
            global_cap = config.get("roster_cap", DEFAULT_ROSTER_CAP)
            for role_id, team_info in self.selected_teams_by_role_id.items():
                team_name = team_info["name"]
                team_data_dict[team_name] = {"role_id": role_id, "emoji": team_info["emoji"], "roster_cap": global_cap, "name": team_name}
                team_roles_legacy_dict[team_name] = role_id
                log_summary.append(f"• Team: {team_info['emoji']} {team_name} (Role ID: {role_id})")

        # Apply selected roles
        perm_settings_dict = config.setdefault("permission_settings", {})
        for role_conf_key, role_id_val in self.selected_roles_by_type.items():
            if role_id_val: # If a role was selected (not None)
                perm_settings_dict[role_conf_key] = [role_id_val] # Assuming single role for these by default from autosetup
                role_obj = guild.get_role(role_id_val)
                log_summary.append(f"• Role {self.role_type_map[role_conf_key]}: {role_obj.name if role_obj else 'ID '+str(role_id_val)}")

        # Apply selected channels
        log_ch_dict = config.setdefault("log_channels", {})
        ann_ch_dict = config.setdefault("announcement_channels", {})
        notif_set_dict = config.setdefault("notification_settings", {})
        for chan_conf_key, chan_id_val in self.selected_channels_by_type.items():
            if chan_id_val:
                chan_obj = guild.get_channel(chan_id_val)
                chan_mention_log = chan_obj.name if chan_obj else 'ID '+str(chan_id_val)
                if chan_conf_key == "reminders_channel_id": notif_set_dict[chan_conf_key] = chan_id_val
                elif chan_conf_key in get_default_config().get("announcement_channels",{}): ann_ch_dict[chan_conf_key] = chan_id_val
                else: log_ch_dict[chan_conf_key] = chan_id_val # Default to log_channels
                log_summary.append(f"• Channel {chan_conf_key.replace('_',' ').title()}: #{chan_mention_log}")

        save_guild_config(self.guild_id, config) # Save all changes at once
        await log_action(guild, "SETUP (AUTO)", interaction.user, "\n".join(log_summary), "autosetup_confirmed")

        final_embed = EmbedBuilder.success("✅ Auto-Setup Applied", "Selected configurations have been saved.")
        if interaction.message: await interaction.edit_original_response(embed=final_embed, view=None)
        else: await interaction.followup.send(embed=final_embed, ephemeral=True)
        self.stop()

    async def _cancel_callback(self, interaction: discord.Interaction):
        await interaction.response.edit_message(embed=EmbedBuilder.info("Auto-Setup Cancelled", "No changes were applied."), view=None)
        self.stop()


class TeamRemoveConfirmationView(discord.ui.View):
    def __init__(self, setup_cog_ref, guild_config_live_ref, guild_id_val: int, team_name_to_remove: str, role_id_associated: Optional[int]):
        super().__init__(timeout=180)
        self.cog = setup_cog_ref
        self.guild_config = guild_config_live_ref # Direct reference to live config
        self.guild_id = guild_id_val
        self.team_name = team_name_to_remove
        self.role_id = role_id_associated
        self.should_delete_role_flag = True # Default to deleting the role

        self.toggle_role_delete_button = discord.ui.Button(label=f"Delete Role: {'Yes' if self.should_delete_role_flag else 'No'}",
                                                           style=discord.ButtonStyle.success if self.should_delete_role_flag else discord.ButtonStyle.secondary,
                                                           custom_id="toggle_delete_role_on_remove", row=0)
        self.toggle_role_delete_button.callback = self.toggle_delete_role_callback
        self.add_item(self.toggle_role_delete_button)

        confirm = discord.ui.Button(label="Confirm Removal", style=discord.ButtonStyle.danger, custom_id="confirm_remove_final", row=1)
        confirm.callback = self.confirm_remove_callback
        self.add_item(confirm)
        cancel = discord.ui.Button(label="Cancel", style=discord.ButtonStyle.grey, custom_id="cancel_remove_final", row=1)
        cancel.callback = self.cancel_remove_callback
        self.add_item(cancel)

    async def toggle_delete_role_callback(self, interaction: discord.Interaction):
        self.should_delete_role_flag = not self.should_delete_role_flag
        self.toggle_role_delete_button.label = f"Delete Role: {'Yes' if self.should_delete_role_flag else 'No'}"
        self.toggle_role_delete_button.style = discord.ButtonStyle.success if self.should_delete_role_flag else discord.ButtonStyle.secondary
        await interaction.response.edit_message(view=self)

    async def confirm_remove_callback(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True) # Defer before processing
        try:
            team_data_dict = self.guild_config.setdefault("team_data", {})
            team_roles_legacy_dict = self.guild_config.setdefault("team_roles", {})

            removed_from_data = team_data_dict.pop(self.team_name, None) is not None
            removed_from_legacy = team_roles_legacy_dict.pop(self.team_name, None) is not None

            role_delete_status_log = ""
            role_delete_status_msg = ""
            if self.should_delete_role_flag and self.role_id:
                role_obj_to_delete = interaction.guild.get_role(self.role_id)
                if role_obj_to_delete:
                    try:
                        await role_obj_to_delete.delete(reason=f"Team '{self.team_name}' removed by {interaction.user.name}")
                        role_delete_status_log = f"Associated role '{role_obj_to_delete.name}' DELETED."
                        role_delete_status_msg = " The associated role was also deleted."
                    except discord.Forbidden:
                        role_delete_status_log = f"FAILED to delete role '{role_obj_to_delete.name}' (Permissions)."
                        role_delete_status_msg = " Failed to delete role: Permissions missing."
                    except discord.HTTPException as e_http:
                        role_delete_status_log = f"FAILED to delete role '{role_obj_to_delete.name}' (HTTP Error: {e_http})."
                        role_delete_status_msg = f" Failed to delete role: Discord API error ({e_http.status})."
                else:
                    role_delete_status_log = "Role ID was configured but role not found."
                    role_delete_status_msg = " Associated role ID was found in config, but role itself not found on server."
            elif self.role_id:
                role_delete_status_log = "Associated role was explicitly PRESERVED."
                role_delete_status_msg = " The associated role was not deleted as per choice."
            else: # No role_id was associated
                role_delete_status_log = "No specific role ID was associated with the team in config."
                role_delete_status_msg = " No specific role was linked to this team name in the primary config."

            if removed_from_data or removed_from_legacy:
                save_guild_config(self.guild_id, self.guild_config) # Save changes
                final_log_msg = f"Removed team '{self.team_name}'. {role_delete_status_log}"
                await log_action(interaction.guild, "SETUP", interaction.user, final_log_msg, "removeteam_confirmed")
                final_user_msg = f"Team '{self.team_name}' removed from configuration.{role_delete_status_msg}"
                await interaction.edit_original_response(embed=EmbedBuilder.success("Team Removed", final_user_msg), view=None)
            else: # Should not happen if initial check in /removeteam was correct
                await interaction.edit_original_response(embed=EmbedBuilder.error("Not Found", "Team was already removed or not found."), view=None)
            self.stop()
        except Exception as e:
            logger.error(f"Error confirming team removal for guild {self.guild_id}: {e}", exc_info=True)
            await interaction.edit_original_response(embed=EmbedBuilder.error("Error", str(e)), view=None)
            self.stop()

    async def cancel_remove_callback(self, interaction: discord.Interaction):
        await interaction.response.edit_message(embed=EmbedBuilder.info("Cancelled", "Team removal cancelled."), view=None)
        self.stop()


async def setup(bot: commands.Bot):
    await bot.add_cog(SetupCommands(bot))
    logger.info("SetupCommands Cog Loaded.")
