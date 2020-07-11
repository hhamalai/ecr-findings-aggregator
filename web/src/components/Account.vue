<template>
    <div>
        <h2>{{ account.account_name }} ({{account.account_id}})</h2>
        <div>
            <div v-for="region in account.regions"
                 v-bind:key="region.region">
                <Region v-bind:region="region" v-bind:selected_cve="selected_cve"></Region>
            </div>
        </div>
    </div>
</template>

<script>
    import Region from "./Region";

    export default {
        name: 'Account',
        components: {
            Region
        },
        props: ['account', 'selected_cve'],
    }
</script>